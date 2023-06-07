#include "server.h"

#define BUFFER_SIZE 8192
#define MAX_CONNECTIONS 15
#define DEFAULT_PORT 5152


struct Server::IP_Packet {
    uint16_t version_hlength_tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint16_t time_to_live_and_protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t* options; 

};

struct Server::TCP_Packet {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint16_t data_offset_and_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t* options_and_data;

};

struct Server::UDP_Packet {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t* data;
};

struct Server::ip_port_addr{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
};


Server::Server(std::string config) {
    parse_config(config);
    //char* packet = "\x47\x00\x00\x35\x1e\x84\x40\x00\x40\x06\xcb\x49\xc0\xa8\x01\x02\xac\x10\x00\x0a\x10\x00\x00\x50\x60\x70\x70\x70\x04\xd2\x00\x50\x00\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00\xac\x58\x00\x00\x10\x50\x20\x50\x60";
    // IP_Packet parsed_header = parse_IPv4_Header(packet);
    // printIPv4Header(parsed_header);
    // uint16_t protocol = static_cast<uint16_t>(parsed_header.time_to_live_and_protocol & 0x00FF);
    // if(protocol == 6){
    //     TCP_Packet tcp = get_tcp_packet(parsed_header,packet);
    //     print_tcp_packet(tcp);
    // }
    // else if(protocol == 17){
    //     UDP_Packet udp = get_udp_packet(parsed_header,packet);
    //     print_udp_packet(udp);
    // }

    // printIPv4Header(parsed_header);
    // bool isvalid = valid_checksum(parsed_header,packet);
    // std::cout<<isvalid<<'\n';


    wan_ip_bin = convert_ip_to_binary(wan_ip);


    lan_ip_bin = convert_ip_to_binary(lan_ip);

    local_ip_bin = convert_ip_to_binary(local_ip);
    // std::cout <<"Should return true \n";
    // std::cout << "Checking excluded address function: " << check_excluded_ip_address(convert_ip_to_binary("192.168.1.200"),convert_ip_to_binary("10.0.0.10"),80,5800)<<std::endl;
    // std::cout <<"Should return true \n";
    // std::cout << "Checking excluded address function: " << check_excluded_ip_address(convert_ip_to_binary("10.0.0.10"),convert_ip_to_binary("192.168.1.10"),5800,80)<<std::endl;

    // std::cout <<"Should also return false \n";
    // std::cout << "Checking excluded address function: " << check_excluded_ip_address(convert_ip_to_binary("10.0.0.10"),convert_ip_to_binary("192.168.1.10"),100,443)<<std::endl;



    // std::cout <<"Should also return false \n";
    // std::cout << "Checking excluded address function: " << check_excluded_ip_address(convert_ip_to_binary("10.0.0.10"),convert_ip_to_binary("192.168.1.10"),100,3000)<<std::endl;
    // std::cout<<local_ip_bin<<std::endl;
    // std::cout<<wan_ip_bin<<std::endl;
    // std::cout<<lan_ip_bin<<std::endl;
    run_server();
}


Server::IP_Packet Server::parse_IPv4_Header(char* packet) {
    IP_Packet header;

    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(packet);
    header.version_hlength_tos = (buffer[0] << 8 )| buffer[1];
    header.total_length = (buffer[2] << 8) | buffer[3];
    header.identification = (buffer[4] << 8) | buffer[5];
    // header.flags_and_fragment_offset = (((header.flags_and_fragment_offset >> 8) & buffer[6]) << 8)| buffer[7];
    header.flags_and_fragment_offset = (buffer[6] << 8) | buffer[7];
    header.time_to_live_and_protocol = (buffer[8] << 8) | buffer[9];
    header.header_checksum = (buffer[10] << 8) | buffer[11];
    header.source_ip = (buffer[12] << 24) | (buffer[13] << 16) | (buffer[14] << 8) | buffer[15];
    header.destination_ip = (buffer[16] << 24) | (buffer[17] << 16) | (buffer[18] << 8) | buffer[19];
    //Need the options field as well to calculate the checksum for the IP packet.
    uint16_t header_length = (header.version_hlength_tos & 0x0F00) >> 8; 
    size_t options_length = (header_length - 5) * 4 ;
    const uint8_t* options_buffer = buffer + 20;
    if(options_length){
        header.options = new uint8_t[options_length];
        memcpy(header.options,options_buffer,options_length);
        }
    else{
        header.options = nullptr;
    }
    return header;

}

Server::TCP_Packet Server::get_tcp_packet(IP_Packet ip_header,char* packet) {
    uint16_t ipv4_total_length = ip_header.total_length;
    uint16_t ipv4_header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);

    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(packet);
    int offset = ipv4_header_length * 4;

    TCP_Packet tcp_packet;
    const uint8_t* tcp_packet_buffer = buffer + offset;

    // Create a TCP_Packet struct and populate its fields from the buffer

    tcp_packet.source_port = (tcp_packet_buffer[0] << 8) | tcp_packet_buffer[1];
    tcp_packet.destination_port = (tcp_packet_buffer[2] << 8) | tcp_packet_buffer[3];
    tcp_packet.sequence_number = (tcp_packet_buffer[4] << 24) | (tcp_packet_buffer[5] << 16) | (tcp_packet_buffer[6] << 8) | tcp_packet_buffer[7];
    tcp_packet.acknowledgment_number = (tcp_packet_buffer[8] << 24) | (tcp_packet_buffer[9] << 16) | (tcp_packet_buffer[10] << 8) | tcp_packet_buffer[11];
    tcp_packet.data_offset_and_flags = (tcp_packet_buffer[12] << 8) | tcp_packet_buffer[13];
    tcp_packet.window_size = (tcp_packet_buffer[14] << 8) | tcp_packet_buffer[15];
    tcp_packet.checksum = (tcp_packet_buffer[16] << 8) | tcp_packet_buffer[17];
    tcp_packet.urgent_pointer = (tcp_packet_buffer[18] << 8) | tcp_packet_buffer[19];


    //Copy the rest of the data to calculate the checksum later.

    // int data_offset = (tcp_packet_buffer[12] & 0xF0 >> 4);
    uint16_t tcp_packet_length = ipv4_total_length - (ipv4_header_length * 4);
    const uint8_t* options_and_data_buffer = tcp_packet_buffer + 20;
    size_t options_and_data_length = tcp_packet_length - 20;

    if(options_and_data_length){
        tcp_packet.options_and_data = new uint8_t[options_and_data_length];
        memcpy(tcp_packet.options_and_data, options_and_data_buffer, options_and_data_length);
    }
    else{
        tcp_packet.options_and_data = nullptr;
    }
    return tcp_packet;
}


Server::UDP_Packet Server::get_udp_packet(IP_Packet ip_header,char* packet) {

    // uint16_t ipv4_total_length = ip_header.total_length;
    uint16_t ipv4_header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);

    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(packet);
    int offset = ipv4_header_length * 4;

    UDP_Packet udp_packet;
    const uint8_t* udp_packet_buffer = buffer + offset;
    udp_packet.source_port = (udp_packet_buffer[0] << 8) | udp_packet_buffer[1];
    udp_packet.destination_port = (udp_packet_buffer[2] << 8) | udp_packet_buffer[3];
    udp_packet.length = (udp_packet_buffer[4] << 8) | udp_packet_buffer[5];
    udp_packet.checksum = (udp_packet_buffer[6] << 8) | udp_packet_buffer[7];
    uint16_t udp_length_data = udp_packet.length - 8;
    const uint8_t* udp_data_buffer = udp_packet_buffer + 8;

    if(udp_length_data){
        udp_packet.data = new uint8_t[udp_length_data];
        memcpy(udp_packet.data,udp_data_buffer,udp_length_data);
    }

    else{
        udp_packet.data = nullptr;
    }
    return udp_packet;
}


std::pair<uint16_t,uint16_t> Server::calc_new_checksum(IP_Packet ip_header, char* packet){

    uint16_t protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    uint16_t header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);
    uint16_t ip_total_length = ip_header.total_length;


    //calculate the ip_checksum
    IP_Packet ip_copy = ip_header;
    ip_copy.header_checksum = 0;

    uint32_t ip_copy_sum;

    ip_copy_sum = calculate_checksum(&ip_copy,sizeof(ip_copy) - sizeof(ip_copy.options) - 4,0);

    if(ip_copy.options != nullptr){
        ip_copy_sum += calculate_checksum(ip_copy.options,header_length * 4 -20,1);
    }


    ip_copy_sum = (ip_copy_sum & 0xFFFF) + (ip_copy_sum >> 16);

    while (ip_copy_sum > 0xFFFF) {
        ip_copy_sum = (ip_copy_sum & 0xFFFF) + (ip_copy_sum >> 16);
    }
    uint16_t ip_checksum = ip_copy_sum & 0xFFFF;
    ip_checksum = ~ip_checksum;


    uint32_t transport_checksum = 0;
    uint16_t final_checksum = 0;
    uint16_t current_checksum = 0;

    // Both psuedo_header for UDP and TCP are the same.
    uint8_t pseudo_header[12];
    // Copy the source IP address (32 bits) into the pseudo header
    memcpy(pseudo_header, &ip_header.source_ip, sizeof(uint32_t));
    // Copy the destination IP address (32 bits) into the pseudo header
    memcpy(pseudo_header + 4, &ip_header.destination_ip, sizeof(uint32_t));

    uint16_t res_and_protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    memcpy(pseudo_header + 8, &res_and_protocol, sizeof(uint16_t));

    // Copy the TCP/UDP length (16 bits) into the pseudo header
    uint16_t transport_length = static_cast<uint16_t>(ip_total_length - header_length * 4);
    memcpy(pseudo_header + 10, &transport_length, sizeof(uint16_t));


    transport_checksum += calculate_checksum(pseudo_header, sizeof(pseudo_header),0);

    
    if(protocol == 6){
        TCP_Packet tcp_copy = get_tcp_packet(ip_header,packet);
        current_checksum = tcp_copy.checksum;
        tcp_copy.checksum = 0;

        transport_checksum += calculate_checksum(&tcp_copy.source_port, sizeof(tcp_copy) - sizeof(tcp_copy.options_and_data) - 4, 0);

        if(tcp_copy.options_and_data != nullptr){
    
            transport_checksum += calculate_checksum(tcp_copy.options_and_data, transport_length - 20, 1);
        }

        //If ip_copy_sum ends up being greater than 16 bits after adding two calll to calculate_checksum twice then we carry the bits over again.
        transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        
        while (transport_checksum > 0xFFFF) {
            transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        }
        final_checksum = transport_checksum & 0xFFFF;
        //Cast it to a 16 bit unsigned int after the carry bits are added back in.
        final_checksum = ~final_checksum;

    }
    else if(protocol == 17){
        UDP_Packet udp_copy = get_udp_packet(ip_header,packet);
        current_checksum = udp_copy.checksum;
        udp_copy.checksum = 0;

        transport_checksum += calculate_checksum(&udp_copy, sizeof(udp_copy) - sizeof(udp_copy.data), 0);
        
        // std::cout << "size udp_copy" << sizeof(udp_copy) << std::endl;

        if(udp_copy.data != nullptr){
            transport_checksum += calculate_checksum(udp_copy.data, transport_length - 8, 1);
        }

        while (transport_checksum > 0xFFFF) {
            transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        }
        
        final_checksum = transport_checksum & 0xFFFF;
        //Cast it to a 16 bit unsigned int after the carry bits are added back in.
        final_checksum = ~final_checksum;
    }
    //Calculate ip check sum, we can simply call calculate_checksum with the ipv4_header as our input.
    // std::cout << "ip check_sum: " << ip_checksum << '\n';
    // std::cout << "transport check_sum: " << final_checksum << '\n';
    //If either of the checksum fails for tcp/ip layer then we return false.

    auto new_checksums = std::make_pair(htons(ip_checksum),htons(final_checksum));

    return new_checksums;

}


bool Server::valid_checksum(IP_Packet ip_header, char* packet){

    uint16_t protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    uint16_t header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);
    uint16_t ip_total_length = ip_header.total_length;


    //calculate the ip_checksum
    IP_Packet ip_copy = ip_header;
    ip_copy.header_checksum = 0;

    uint32_t ip_copy_sum;

    ip_copy_sum = calculate_checksum(&ip_copy,sizeof(ip_copy) - sizeof(ip_copy.options) - 4,0);

    if(ip_copy.options != nullptr){
        ip_copy_sum += calculate_checksum(ip_copy.options,header_length * 4 -20,1);
    }


    ip_copy_sum = (ip_copy_sum & 0xFFFF) + (ip_copy_sum >> 16);

    while (ip_copy_sum > 0xFFFF) {
        ip_copy_sum = (ip_copy_sum & 0xFFFF) + (ip_copy_sum >> 16);
    }
    uint16_t ip_checksum = ip_copy_sum & 0xFFFF;
    ip_checksum = ~ip_checksum;


    uint32_t transport_checksum = 0;
    uint16_t final_checksum = 0;
    uint16_t current_checksum = 0;

    // Both psuedo_header for UDP and TCP are the same.
    uint8_t pseudo_header[12];
    // Copy the source IP address (32 bits) into the pseudo header
    memcpy(pseudo_header, &ip_header.source_ip, sizeof(uint32_t));
    // Copy the destination IP address (32 bits) into the pseudo header
    memcpy(pseudo_header + 4, &ip_header.destination_ip, sizeof(uint32_t));

    uint16_t res_and_protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    memcpy(pseudo_header + 8, &res_and_protocol, sizeof(uint16_t));

    // Copy the TCP/UDP length (16 bits) into the pseudo header
    uint16_t transport_length = static_cast<uint16_t>(ip_total_length - header_length * 4);
    memcpy(pseudo_header + 10, &transport_length, sizeof(uint16_t));


    transport_checksum += calculate_checksum(pseudo_header, sizeof(pseudo_header),0);

    
    if(protocol == 6){
        TCP_Packet tcp_copy = get_tcp_packet(ip_header,packet);
        current_checksum = tcp_copy.checksum;
        tcp_copy.checksum = 0;

        transport_checksum += calculate_checksum(&tcp_copy.source_port, sizeof(tcp_copy) - sizeof(tcp_copy.options_and_data) - 4, 0);

        if(tcp_copy.options_and_data != nullptr){

            transport_checksum += calculate_checksum(tcp_copy.options_and_data, transport_length - 20, 1);
        }

        //If ip_copy_sum ends up being greater than 16 bits after adding two calll to calculate_checksum twice then we carry the bits over again.
        transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        
        while (transport_checksum > 0xFFFF) {
            transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        }
        final_checksum = transport_checksum & 0xFFFF;
        //Cast it to a 16 bit unsigned int after the carry bits are added back in.
        final_checksum = ~final_checksum;

    }
    else if(protocol == 17){
        UDP_Packet udp_copy = get_udp_packet(ip_header,packet);
        current_checksum = udp_copy.checksum;
        udp_copy.checksum = 0;
    

        transport_checksum += calculate_checksum(&udp_copy, sizeof(udp_copy) - sizeof(udp_copy.data), 0);
        
        std::cout << "size udp_copy" << sizeof(udp_copy) << std::endl;

        if(udp_copy.data != nullptr){
            transport_checksum += calculate_checksum(udp_copy.data, transport_length - 8, 1);
        }

        while (transport_checksum > 0xFFFF) {
            transport_checksum = (transport_checksum & 0xFFFF) + (transport_checksum >> 16);
        }
        
        final_checksum = transport_checksum & 0xFFFF;
        //Cast it to a 16 bit unsigned int after the carry bits are added back in.
        final_checksum = ~final_checksum;
    }
    //Calculate ip check sum, we can simply call calculate_checksum with the ipv4_header as our input.
    // std::cout << "ip check_sum: " << ip_checksum << '\n';
    // std::cout << "transport check_sum: " << final_checksum << '\n';
    //If either of the checksum fails for tcp/ip layer then we return false.
    // if(final_checksum != current_checksum){
    //     std::cout<<"Tcp checksum failed"<<'\n';
    // }
    // if(ip_checksum != ip_header.header_checksum){
    //     std::cout<<"ip checksum failed"<<'\n';
    // }


    if((final_checksum != current_checksum) | (ip_checksum != ip_header.header_checksum)){
        return false;
    }
    else{
        return true;
    }
}

uint32_t Server::calculate_checksum(void* data, size_t length, int option) {
    uint16_t* buffer = reinterpret_cast<uint16_t*>(data);
    uint32_t sum = 0;

    for (size_t i = 0; i < length / 2; ++i) {
        //std::cout << "val: " << (!option ? buffer[i] : ntohs(buffer[i])) << "\niteration : " << i << '\n';
        sum += !option ? (buffer[i]) : ntohs(buffer[i]);
        ///std::cout<<"sum: " << sum <<" iteration: " << i << '\n';
    }

    // If the length is odd, add the last byte
    if (length % 2 != 0) {
        uint16_t odd_byte = static_cast<uint16_t>(reinterpret_cast<uint8_t*>(data)[length - 1]);
        //std::cout<< "val odd byte " << (odd_byte << 8) << '\n';
        sum += (odd_byte << 8);  // Pad the odd byte on the right side
        //std::cout << "sum odd byte: " << sum << " iteration: " << '\n';
    }


    return sum;
}

// char* Server::deduct_TTL(char* packet) {
//     //deduct the TTL packet by one
//     uint8_t* buffer = reinterpret_cast<uint8_t*>(packet);
//     //if ttl is 0 or 1 by the time it is recieved we return nullptr to drop the packet.
//     if((buffer[8] == 0) | (buffer[8] == 1)){
//         return nullptr;
//     }
//     else{
//          --buffer[8];
//     }
//     return packet;
// }

Server::ip_port_addr Server::get_ip_port_vals(char* packet){
    ip_port_addr addr_block;
    IP_Packet ip_header = parse_IPv4_Header(packet);
    uint16_t header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);
    uint8_t * packet_buffer = reinterpret_cast<uint8_t*> (packet);

    addr_block.source_ip = (packet_buffer[12] << 24) | (packet_buffer[13] << 16) | (packet_buffer[14] << 8) | packet_buffer[15];
    addr_block.dest_ip = (packet_buffer[16] << 24) | (packet_buffer[17] << 16) | (packet_buffer[18] << 8) | packet_buffer[19];

    packet_buffer = packet_buffer + header_length * 4;

    addr_block.source_port = (packet_buffer[0] << 8) | packet_buffer[1];
    addr_block.dest_port = (packet_buffer[2] << 8) | packet_buffer[3];

    return addr_block;


}
//function to change the packet source ip/ports and dest ip/ports
char* Server::change_packet_vals(char* buffer,uint32_t source_ip,uint32_t dest_ip, uint16_t source_port, uint16_t dest_port){
    char* packet = buffer;
    IP_Packet ip_header = parse_IPv4_Header(packet);
    uint16_t header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);
    uint8_t * packet_buffer = reinterpret_cast<uint8_t*> (packet);

    //if ttl is 0 or 1 by the time it is recieved we return nullptr to drop the packet.
    if((packet_buffer[8] == 0) | (packet_buffer[8] == 1)){
        return nullptr;
    }
    else{
         --packet_buffer[8];
    }

    memcpy(packet_buffer + 12, &source_ip, sizeof(uint32_t));
    memcpy(packet_buffer + 16, &dest_ip, sizeof(uint32_t));

    packet_buffer = packet_buffer + header_length * 4;

    memcpy(packet_buffer, &source_port, sizeof(uint16_t));
    memcpy(packet_buffer +2 , &dest_port, sizeof(uint16_t));

    ip_header = parse_IPv4_Header(packet);
    
    auto new_checksums = calc_new_checksum(ip_header,packet);
    header_length = ((ip_header.version_hlength_tos & 0x0F00) >> 8);
    packet_buffer -= header_length * 4;

    memcpy(packet_buffer + 10, &new_checksums.first,sizeof(uint16_t));
    
    packet_buffer += header_length * 4;


    uint16_t protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    
    if(protocol == 6){
        memcpy(packet_buffer + 16,&new_checksums.second,sizeof(uint16_t));
    }
    else{
        memcpy(packet_buffer + 6,&new_checksums.second,sizeof(uint16_t));
    }

    return packet;
}

//This function replaces the destination port with the actual port forwarding map

int Server::get_forwarding_socket(char* packet){

    ip_port_addr addr_block = get_ip_port_vals(packet);

    uint32_t dest_ip = addr_block.dest_ip;

    int client_socket;
    auto it = forward_table.begin();
    client_socket = it->second;// defaults the client socket to the first file descriptor for the ip.
    it = forward_table.find(convert_uint32_to_ip(dest_ip));
    if(it != forward_table.end()){
        client_socket = it->second;
    }
    // for(auto it = forward_table.begin();it != forward_table.end();++it){
    //     uint32_t ip_value = convert_ip_to_binary(it->first);
    //     if(ip_value == dest_ip){
    //         //If the destination ip is any of the ip addresses within the local lan we get the index of the map to get the correct port
    //         client_socket = it->second;
    //     }
    // }
    return client_socket;

}
char* Server::process_packet(char* buffer){
    char* packet = buffer;
    // IP_Packet ip_header = parse_IPv4_Header(packet);
    ip_port_addr addr_block = get_ip_port_vals(packet);
    IP_Packet ip_header = parse_IPv4_Header(packet);

    uint32_t source_ip = addr_block.source_ip;
    uint32_t dest_ip = addr_block.dest_ip;
    uint16_t source_port = addr_block.source_port;
    uint16_t dest_port = addr_block.dest_port;

    //New values that we will use to rewrite.
    uint32_t new_source_ip = 0;
    uint32_t new_dest_ip = 0;
    uint16_t new_source_port = 0;
    uint16_t new_dest_port = 0;

    if(!valid_checksum(ip_header,packet)){
            return nullptr;
    }
    if(check_excluded_ip_address(source_ip,dest_ip,source_port,dest_port)){
                    //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
                    return nullptr;
    }

    //if the source ip is the wan ip then we are forwarding a messaage from the internet to someone in the lan.
    if(dest_ip == wan_ip_bin){
        bool port_match_found = false;
        for (auto it = port_map.begin(); it != port_map.end(); ++it) {
            //if the dest port is equal to any wan port dictated in the list of port mappings then we can forward the packet.
            if(it == port_map.find(wan_ip)){
                continue;
            }
            auto& array_port_pair = it->second;
            int size = array_port_pair.size();
            for(int i = 0; i < size; i++){
                if(dest_port == array_port_pair[i].second){
                    //We set the source ip to be the same and set the destination of the packet to be the port mapped one.
                    new_source_ip = source_ip;
                    new_dest_ip = convert_ip_to_binary(it->first);
                    new_source_port = source_port;
                    new_dest_port = array_port_pair[i].first;

                    port_match_found = true;

                    if(check_excluded_ip_address(new_source_ip,new_dest_ip,new_source_port,new_dest_port)){
                        //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
                        return nullptr;
                    }
                    
                    packet = change_packet_vals(packet,htonl(new_source_ip),htonl(new_dest_ip),htons(new_source_port),htons(new_dest_port));
                    //packet = deduct_TTL(packet);
                    return packet;
                    }
                }
            if(port_match_found){
                break;
            }
        // std::cout << "LAN IP: " << it->first << "\nLAN Port: " << it->second.first << " WAN Port: " << it->second.second << std::endl;
        }
        if(!port_match_found){
            //We make a place holder for wan_ip in the map.
            // port_map[wan_ip].push_back(std::make_pair(0,++dyn_port_number));
            return nullptr;
        }
    }

    //Handle LAN traffic here
    else if((source_ip & lan_subnet_mask) == (lan_ip_bin & lan_subnet_mask) && (dest_ip & lan_subnet_mask) == (lan_ip_bin & lan_subnet_mask)){
        //Honestly we do nothing and just forward the packet as is to the LAN ip address with no changes, only to the time to live and header checksums.
        if(check_excluded_ip_address(source_ip,dest_ip,source_port,dest_port)){
                    //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
                    return nullptr;
            }
        // std::cout<<"Forwarding between lan Ips"<<std::endl;
        packet = change_packet_vals(packet,htonl(source_ip),htonl(dest_ip),htons(source_port),htons(dest_port));
        return packet;
    }
    //Handle packets being forwarded from the lan to the internet
    else if((source_ip & lan_subnet_mask )== (lan_ip_bin & lan_subnet_mask)){
        //Check the wan_ip entry to see if any ip address from the lan is trying to connect to a previous port sent to wan ip before.
        //auto it = port_map.find(wan_ip);
        // if(it != port_map.end()){
        //     auto& array_port_pair = it->second;
        //     int size_vector = (array_port_pair).size(); 
        //     for(int i = 0; i < size_vector; i++){
        //         if(dest_port == array_port_pair[i].first){
        //             auto lan_it = port_map.find(convert_uint32_to_ip(source_ip));
        //             lan_it->second.push_back(std::make_pair(source_port,array_port_pair[i].second));
        //             array_port_pair[i].second+=1;
        //             array_port_pair[i].first+=1;
        //             // array_port_pair.erase(array_port_pair.begin() + i);
        //             break;
        //         }
        //     }
        // }
        auto iter = port_map.find(convert_uint32_to_ip(source_ip));
        if(iter != port_map.end()){
                auto& array_port_pair = iter->second;
                int size = array_port_pair.size();
                for(int i = 0; i < size;i++){
                    if(source_port == array_port_pair[i].first){
                        new_source_ip = wan_ip_bin;
                        new_dest_ip = dest_ip;
                        new_source_port = array_port_pair[i].second;
                        new_dest_port = dest_port;
                        if(check_excluded_ip_address(new_source_ip,new_dest_ip,new_source_port,new_dest_port)){
                            //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
                            return nullptr;
                        }
                        packet = change_packet_vals(packet,htonl(new_source_ip),htonl(new_dest_ip),htons(new_source_port),htons(new_dest_port));
                        //packet = deduct_TTL(packet);
                        return packet;
                        }
                    }
                }
        if(iter != port_map.end()){
            auto it = port_map.find(wan_ip);
            auto& wan_port_pair = it->second;
            uint16_t wan_port = wan_port_pair[0].second;

            auto& array_port_pair = iter->second;
            array_port_pair.push_back(std::make_pair(source_port,wan_port));

            new_source_ip = wan_ip_bin;
            new_dest_ip = dest_ip;
            new_source_port = wan_port;
            new_dest_port = dest_port;

            if(check_excluded_ip_address(new_source_ip,new_dest_ip,new_source_port,new_dest_port)){
                //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
                return nullptr;
            }
            wan_port_pair[0].second += 1;

            packet = change_packet_vals(packet,htonl(new_source_ip),htonl(new_dest_ip),htons(new_source_port),htons(new_dest_port));
            //packet = deduct_TTL(packet);
            return packet;
            }
        }

    // if(check_excluded_ip_address(new_source_ip,new_dest_ip,new_source_port,new_dest_port)){
    //     //if for some reason the configuration is excluded from the acl list then we return a nullptr of a char* 
    //     return nullptr;
    // }
    // packet = change_packet_vals(packet,htonl(new_source_ip),htonl(new_dest_ip),htons(new_source_port),htons(new_dest_port));
    // //packet = deduct_TTL(packet);
    // If none of these situations apply then we would return a nullptr.
    return nullptr;
}
            

void Server::printIPv4Header(IP_Packet& header) {
    //used for testing parser.
    std::cout << "Version: " << static_cast<int>((header.version_hlength_tos & 0xF000 )>> 12) << '\n';
    std::cout << "Header Length: " << static_cast<int>((header.version_hlength_tos & 0x0F00)>>8) << '\n';
    std::cout << "Type of Service: " << static_cast<int>((header.version_hlength_tos) & 0x00FF) << '\n';
    std::cout << "Total Length: " << header.total_length << '\n';
    std::cout << "Identification: " << header.identification << '\n';
    std::cout << "Flags and Fragment Offset: " << header.flags_and_fragment_offset << '\n';
    std::cout << "Time to Live: " << static_cast<int>((header.time_to_live_and_protocol & 0xFF00) >> 8) << '\n';
    std::cout << "Protocol: " << static_cast<int>(header.time_to_live_and_protocol & 0x00FF) << '\n';
    std::cout << "Header Checksum: " << header.header_checksum << '\n';
    std::cout << "Source IP: " << header.source_ip << '\n';
    std::cout << "Destination IP: " << header.destination_ip << '\n';
    // std::cout << "Options :" << header.options << '\n';

    if (header.options!= nullptr) {
        std::cout << "Options and Data: " << header.options << std::endl;
    }
    else {
        std::cout << "Options and Data: <null>" << std::endl;
    }
}

void Server::print_tcp_packet(const TCP_Packet& tcp_packet) {
    std::cout << "Source Port: " << tcp_packet.source_port << std::endl;
    std::cout << "Destination Port: " << tcp_packet.destination_port << std::endl;
    std::cout << "Sequence Number: " << tcp_packet.sequence_number << std::endl;
    std::cout << "Acknowledgment Number: " << tcp_packet.acknowledgment_number << std::endl;
    std::cout << "Data Offset and Flags: " << tcp_packet.data_offset_and_flags << std::endl;
    std::cout << "Window Size: " << tcp_packet.window_size << std::endl;
    std::cout << "Checksum: " << tcp_packet.checksum << std::endl;
    std::cout << "Urgent Pointer: " << tcp_packet.urgent_pointer << std::endl;
    // Assuming options_and_data is a null-terminated string
    if (tcp_packet.options_and_data != nullptr) {
        std::cout << "Options and Data: " << tcp_packet.options_and_data << std::endl;
    }
    else {
        std::cout << "Options and Data: <null>" << std::endl;
    }
}

void Server::print_udp_packet(const UDP_Packet& udp_packet) {
    std::cout << "Source Port: " << udp_packet.source_port << std::endl;
    std::cout << "Destination Port: " << udp_packet.destination_port << std::endl;
    std::cout << "Length: " << udp_packet.length << std::endl;
    std::cout << "Checksum: " << udp_packet.checksum << std::endl;
    // Assuming data is a null-terminated string
    if (udp_packet.data != nullptr) {
        std::cout << "Data: " << udp_packet.data << std::endl;
    }
    else {
        std::cout << "Data: <null>" << std::endl;
    }
}



uint32_t Server::convert_ip_to_binary(const std::string& ip_address) {
    std::stringstream ss(ip_address);
    std::string octet;
    unsigned int result = 0;

    while (std::getline(ss, octet, '.')) {
        unsigned int decimal_octet = std::stoi(octet);
        result = (result << 8) | decimal_octet;
    }

    return result;
}

std::string Server::convert_uint32_to_ip(uint32_t ip) {
    std::stringstream ss;
    ss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.' << (ip & 0xFF);
    return ss.str();
}

// uint32_t Server::convert_ip_to_binary(const std::string& ip_address) {
//     struct in_addr addr;
//     int result = inet_pton(AF_INET, ip_address.c_str(), &(addr));

//     if (result <= 0) {
//         // Failed to convert IP address
//         return 0; // or some appropriate error handling
//     }

//     return ntohl(addr.s_addr);
// }

void Server::parse_config(std::string config){

    std::cout << "Parsing Config" << std::endl;
    std::regex ip_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    std::regex ip_port_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,5}) (\d{1,5}))");
    std::regex acl_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) (\d{1,5})-(\d{1,5}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) (\d+)-(\d+))");
    std::smatch match_regex;


    std::stringstream ss(config);
    std::string line;
    // First line is the router's LAN IP and the WAN IP
    std::getline(ss, line, '\n');
    size_t dwPos = line.find(' ');
    std::string LanIp = line.substr(0, dwPos);
    std::string WanIp = line.substr(dwPos + 1);

    std::cout << "Server's LAN IP: " << LanIp << std::endl
                << "Server's WAN IP: " << WanIp << std::endl;

    wan_ip = WanIp;
    lan_ip = LanIp;
    std::getline(ss, line, '\n');
    //Parse through the first part of the block until first \n character by checking if the line contains

    std::string::const_iterator search(line.cbegin());
    //Parse through each of the blocks until \n character by checking if the line contains the specified expression
    int lan_ip_index = 0;
    while (std::regex_search(search, line.cend(), match_regex, ip_regex)) {
        std::string ip_address = match_regex[1].str();
        lan_index_map[ip_address] = lan_ip_index;
        if(port_map.find(ip_address) == port_map.end()){
            port_map[ip_address] = std::vector<std::pair<uint16_t,uint16_t>>();
        }
        lan_ip_index++;
        std::getline(ss, line, '\n');
        search = line.cbegin();
    }
    std::getline(ss, line, '\n');
    search = line.cbegin();
    while (std::regex_search(search, line.cend(), match_regex, ip_port_regex)) {
        std::string ip_address = match_regex[1].str();
        int lan_port = std::stoi(match_regex[2].str());
        int wan_port = std::stoi(match_regex[3].str());
        
        auto port_pair = std::make_pair(lan_port,wan_port);
        if(port_map.find(ip_address) == port_map.end()){
            std::cerr << "Error, specified port pairing for ip address not defined in LAN: " << ip_address <<std::endl;
            //return;
        }
        port_map[ip_address].push_back(port_pair);
        std::getline(ss, line, '\n');
        search = line.cbegin();
    }
    port_map[wan_ip] = std::vector<std::pair<uint16_t,uint16_t>>();
    port_map[wan_ip].push_back(std::make_pair(0,dyn_port_num));
    std::getline(ss, line, '\n');
    search = line.cbegin();
    while (std::regex_search(search, line.cend(), match_regex, acl_regex)) {
        //Note that the the ip addresses for these blocks will have the form ip_address/subnet mask. Will need to seperate the the string later to check.
        std::string host_ip_address = match_regex[1].str();
        int host_start_port = std::stoi(match_regex[2].str());
        int host_end_port = std::stoi(match_regex[3].str());
        
        std::string client_ip_address = match_regex[4].str();
        int client_start_port = std::stoi(match_regex[5].str());
        int client_end_port = std::stoi(match_regex[6].str());

        auto host_port_range = std::make_pair(host_start_port,host_end_port);
        auto client_port_range = std::make_pair(client_start_port,client_end_port);

        if(exclusion_map.find(host_ip_address) != exclusion_map.end()){
            auto& map = exclusion_map[host_ip_address];
            if(map.find(client_ip_address) == map.end()){
                //makes sure that the same entry isnt being inputted twice.
                exclusion_map[host_ip_address][client_ip_address] = std::make_pair(host_port_range, client_port_range);
            }
        }
        else{
            exclusion_map[host_ip_address] = std::map<std::string, std::pair<exclusion_range, exclusion_range>>();
            exclusion_map[host_ip_address][client_ip_address] = std::make_pair(host_port_range, client_port_range);
        }   

        std::getline(ss, line, '\n');
        search = line.cbegin();
    }
    //output the port mappings of the LAN ip addresses to the WAN ip.
    // for (auto it = port_map.begin(); it != port_map.end(); ++it) {
    //     auto& array_port_pair = it->second;
    //     std::cout << "LAN IP: " << it->first << "\n";
    //     int size = array_port_pair.size();
    //     for(int i = 0; i < size;i++){
    //         std::cout <<" LAN Port: " << array_port_pair[i].first << " WAN Port: " << array_port_pair[i].second << std::endl;
    //     }
    // }
    // //Output the entries of the exclusion map for testing
    // std::cout << "Exclusion Map:" << std::endl;
    // for (const auto& entry : exclusion_map) {
    //     std::cout << "Host IP: " << entry.first << std::endl;
    //     const auto& inner_map = entry.second;
    //     for (const auto& inner_entry : inner_map) {
    //         std::cout << "  Client IP: " << inner_entry.first << std::endl;
    //         const auto& exclusion_range_pair = inner_entry.second;
    //         std::cout << "    Excluded Host Port Ranges: " << exclusion_range_pair.first.first
    //                 << "-" << exclusion_range_pair.first.second << std::endl;
    //         std::cout << "    Excluded Client Port Ranges: " << exclusion_range_pair.second.first
    //                 << "-" << exclusion_range_pair.second.second << std::endl;
    //     }
    // }
    // std::cout<<std::endl;
}

bool Server::check_excluded_ip_address(uint32_t source_ip,uint32_t dest_ip,uint16_t source_port,uint16_t dest_port){
    uint32_t mask_length = 0;
    uint32_t host_ip = 0;
    uint32_t client_ip = 0;
    uint32_t temp_source_ip = 0;
    uint32_t temp_dest_ip = 0;

    uint32_t masked_source_ip = source_ip & lan_subnet_mask;
    uint32_t masked_lan_ip = lan_ip_bin & lan_subnet_mask;

    // std::cout << "source_ip " << source_ip << std::endl;
    // std::cout << "dest_ip " << dest_ip << std::endl;
    for(const auto& entry : exclusion_map){
        std::cout << "Key: " << entry.first << std::endl;
        //Takes the a string with the format "192.168.1.0/24" and converts the first part ip to binary. Takes the last part for the mask." 
        host_ip  = convert_ip_to_binary(entry.first.substr(0,entry.first.find_last_of('/')));
        mask_length = std::stoi(entry.first.substr(entry.first.find_last_of('/') + 1));
        // std::cout << "host_ip " << host_ip << std::endl;
        // std::cout << "mask_length " << mask_length << std::endl;
        //Get the number of bits to actually shift 
        mask_length = 32 - mask_length;
        // std::cout << "mask_length " << mask_length << std::endl;
        //We shift right and left the length of the bit mask for comparison. Then we perform bitwise & with host_ip to find a match.
        temp_source_ip = source_ip >> mask_length << mask_length;
        temp_source_ip = host_ip & temp_source_ip;
        // std::cout << "temp_source_ip " << temp_source_ip <<std::endl;

        // std::cout <<'\n'<< entry.first;
        if(temp_source_ip == host_ip || entry.first == "0.0.0.0/0"){

            const auto& inner_map = entry.second;
            // for(const auto& inner_entry : inner_map){
            //     std::cout << "Key2: " << inner_entry.first << std::endl;
            // }
            for(const auto& inner_entry : inner_map){

                std::cout << "Key2: " << inner_entry.first << std::endl;
                client_ip  = convert_ip_to_binary(inner_entry.first.substr(0,inner_entry.first.find_last_of('/')));
                mask_length = std::stoi(inner_entry.first.substr(inner_entry.first.find_last_of('/') + 1));
                //Get the number of bits to actually shift 
                mask_length = 32 - mask_length;
                // std::cout << "mask length " << mask_length << std::endl;

                //We shift right and left the length of the bit mask for comparison. Then we perform bitwise & with host_ip to find a match.
                temp_dest_ip = dest_ip >> mask_length << mask_length;
                temp_dest_ip = client_ip & temp_dest_ip;
                // std::cout << "temp_dest_ip " << temp_dest_ip <<std::endl;
                // std::cout << "client_ip " << client_ip <<std::endl;
                if(temp_dest_ip == client_ip || inner_entry.first == "0.0.0.0/0"){

                    const auto& exclusion_range_pair = inner_entry.second;
                    int host_range_lower = exclusion_range_pair.first.first;
                    int host_range_upper = exclusion_range_pair.first.second;
                    int client_range_lower = exclusion_range_pair.second.first;
                    int client_range_upper = exclusion_range_pair.second.second;

                    std::cout << "Host Range Lower: " << host_range_lower << "\n";
                    std::cout << "Host Range Upper: " << host_range_upper << "\n";
                    std::cout << "Client Range Lower: " << client_range_lower << "\n";
                    std::cout << "Client Range Upper: " << client_range_upper << "\n";
                    std::cout << "Source Port: " << source_port <<std::endl;
                    std::cout << "Dest Port: " << dest_port <<std::endl;

                    // std::cout << "    Excluded Host Port Ranges: " << exclusion_range_pair.first.first
                    // << "-" << exclusion_range_pair.first.second << std::endl;
                    // std::cout << "    Excluded Client Port Ranges: " << exclusion_range_pair.second.first
                    // << "-" << exclusion_range_pair.second.second << std::endl;

                    if(host_range_lower <= source_port && source_port <= host_range_upper 
                        && client_range_lower <= dest_port && dest_port <= client_range_upper){
                            //Returns true if the ip address pair and port numbers are excluded from eachother.
                            return true;
                        }
                    }
                }
            }
        }
    return false;
}

volatile sig_atomic_t signal_raised = false;

void Server::signalHandler(int signal) {
    signal_raised = true;
}
void Server::run_server(){

    //pthread_t threads[MAX_CONNECTIONS];


    int wan_fd;
    int new_client_socket;

    //Initialize array of sockets to be 0s
    int client_sockets[MAX_CONNECTIONS];
    memset(client_sockets, 0, sizeof(client_sockets));

    // int* client_socket_ptr = client_sockets; 

    std::signal(SIGINT, Server::signalHandler);
    std::signal(SIGTERM, Server::signalHandler);


    int sd,max_sd;
    int activity;
    fd_set read_fds;

    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    int port_number = DEFAULT_PORT;

    if((wan_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        perror("socket");
        exit(1);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = htonl(local_ip_bin);

    memset(server_addr.sin_zero, '\0',sizeof(server_addr.sin_zero));

    /*Fixes error when port number is in use.*/
    int yes=1;

    if(setsockopt(wan_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1){
        perror("Cannot reset socket options on wan_fd");
        exit(1);
    }

    if(setsockopt(wan_fd,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes)) == -1){
        perror("Cannot reuse port");
        exit(1);
    }

    /*Binding the socket*/
    printf("Binding socket to %d\n",port_number);

    
    if(bind(wan_fd, (struct sockaddr*) &server_addr, 
        sizeof(server_addr)) == -1){
            perror("Error in binding the socket");
            exit(1);
        }


    if(listen(wan_fd, 10) == -1){
        perror("Error in listening to socket");
        }

     printf("Listening to socket %d\n",port_number);

     printf("Waiting to accept connections from clients.\n");

    int num_lan_ips = lan_index_map.size();
    // std::cout<<"num_lan_ips: " << num_lan_ips << '\n';
    int map_index = 0;
    
    // FD_ZERO(&read_fds);
    // FD_SET(wan_fd,&read_fds);
    // //std::shared_ptr<Server> self = shared_from_this(); 
    // max_sd = wan_fd;
    while(!signal_raised){
        //Create set of file descriptors
        FD_ZERO(&read_fds);

        //Set the listening server to the set of socket file descriptors Taken from select.c

        FD_SET(wan_fd,&read_fds);
        max_sd = wan_fd;
        for(int i = 0; i < MAX_CONNECTIONS; i++){
            sd = client_sockets[i];
            if(sd > 0){
                FD_SET(sd, &read_fds);
            }
            if(sd > max_sd){
                max_sd = sd;
            }
        }

        activity = select(max_sd+1, &read_fds,NULL,NULL,NULL);

        if((activity < 0) && (errno != EINTR)){
            perror("Error occured with select function.");
        }

        if(FD_ISSET(wan_fd,&read_fds)){
            //Accepting client connections to server 
            new_client_socket = accept(wan_fd, (struct sockaddr*)&client_addr, &client_addr_size);
            if (new_client_socket == -1) {
                perror("Error in accepting client connection from address");
                printf("%s\n", inet_ntoa(client_addr.sin_addr));
            }

            //getting client_ip address and port number and printing it to console.
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,sizeof(client_ip));
            int client_port = ntohs(client_addr.sin_port);
            //printf("Accepted connection from client:\n %s:%d\n", client_ip, client_port);

            if(map_index < num_lan_ips ){
                //intialize actual forwarding table.
                auto iter = lan_index_map.begin();
                std::advance(iter,map_index);
                if(iter != lan_index_map.end()){
                std::string lan_string = iter->first;
                forward_table[lan_string]= new_client_socket;
                }
                map_index++;
            }

            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (client_sockets[i] == 0) {
                        client_sockets[i] = new_client_socket;
                        break;
                    }
            }
        }

        for(int i = 0; i < MAX_CONNECTIONS; i++){
            sd = client_sockets[i];
            if(sd > 0 && FD_ISSET(sd, &read_fds)){
                //printf("Processing client %d\n", i);
                process_client_socket(client_sockets[i]);
                // std::thread processThread(&Server::process_client_socket,this,std::ref(client_sockets[i]));
                // processThread.detach();
                //printf("Client %d: processed successfully\n", i);
            }
            // if(i < num_lan_ips && ){
            //     close(client_sockets[i]);
            //     client_sockets[i] = 0;
            //}
        }
    }
    for(int i = 0; i < MAX_CONNECTIONS;i++){
                close(client_sockets[i]);
                // client_sockets[i] = 0;
            }
            close(wan_fd);
}


void Server::establish_TCP_Connection(char* packet, uint32_t destIP, uint16_t destPort,uint16_t num_bytes) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(destPort);
    server_addr.sin_addr.s_addr = htonl(local_ip_bin);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sockfd);
        return;
    }

    // Connection established, send the payload packet
    if (send(sockfd, packet, num_bytes, 0) == -1) {
        perror("send");
    }

    close(sockfd);
}


void Server::process_client_socket(int& client_socket){
    char buffer[BUFFER_SIZE];
    // Receive data from client if there is data
    memset(buffer,0,BUFFER_SIZE);
    //need to test to see if the null terminating string affects the number of bytes recieved.
    int number_bytes = recv(client_socket, buffer, BUFFER_SIZE,0);

    // std::cout<<"Number Bytes: " << number_bytes<<std::endl;
    //buffer[number_bytes] = '\0';

    // if(number_bytes == 0){
    //     close(client_socket);
    //     client_socket = 0;
    // }

    // printf("Client %d: %s\n", client_socket, buffer);

    char* packet = buffer;
    // IP_Packet ip_header = parse_IPv4_Header(packet);
    // printIPv4Header(ip_header);

    // uint16_t protocol = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    // if(protocol == 6){
    //     TCP_Packet tcp = get_tcp_packet(ip_header,packet);
    //     print_tcp_packet(tcp);
    // }
    // else if(protocol == 17){
    //     UDP_Packet udp = get_udp_packet(ip_header,packet);
    //     print_udp_packet(udp);
    // }
    // bool isvalid = valid_checksum(ip_header,packet);
    // std::cout<<"valid checksum: "<< isvalid <<'\n';

    // std::cout << ip_header.total_length <<std::endl;

    packet = process_packet(packet);

    // std::cout<<"processed packet. client: " << client_socket<<'\n';

    // IP_Packet ip_header1 = parse_IPv4_Header(packet);
    // printIPv4Header(ip_header1);

    // uint16_t protocol1 = static_cast<uint16_t>(ip_header.time_to_live_and_protocol & 0x00FF);
    // if(protocol1 == 6){
    //     TCP_Packet tcp = get_tcp_packet(ip_header,packet);
    //     print_tcp_packet(tcp);
    // }
    // else if(protocol1 == 17){
    //     UDP_Packet udp = get_udp_packet(ip_header,packet);
    //     print_udp_packet(udp);
    // }
    // bool isvalid1 = valid_checksum(ip_header,packet);
    // std::cout<<"valid checksum: "<< isvalid1 <<'\n';


    if(packet != nullptr){
        int forward_socket = get_forwarding_socket(packet);
        // for(auto it = forward_table.begin();it != forward_table.end();it++){
        //     // std::cout<<"client ip: " << it->first <<"socket_fd:" << it->second <<'\n';
        // }
        // std::cout <<forward_socket<<std::endl;

        // uint32_t destination_ip = addr_block.dest_ip;
        // uint16_t destination_port = addr_block.dest_port;

        if(send(forward_socket, packet, number_bytes, 0) == -1){
            perror("Sending error");
        }
        //establish_TCP_Connection(packet,destination_ip,destination_port,number_bytes);
    }
    //In any case close the socket after the payload has been sent successfully. 
    }