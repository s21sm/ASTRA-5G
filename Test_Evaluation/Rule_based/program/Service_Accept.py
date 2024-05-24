import subprocess 
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output 

def service_accept_factor_retrieve_text(uplink_command,downlink_command,key_estbl_status,message_encoding_type,pcap_file_path,dl_com_invoke_line):

    pcap_file = pcap_file_path
  
    if key_estbl_status:
        key_estbl_status_str = 'Completed'
    else:
        key_estbl_status_str = 'Not completed'
        

    factor_text = (
        'Hooking point:  ' + convert_to_readable(uplink_command) + '\n' +
        'Downlink command: ' + convert_to_readable(downlink_command) + '\n' +
        '5G-AKA: ' + key_estbl_status_str + '\n' +
        'Message send as: ' + message_encoding_type + '\n' 
    )
    

    return factor_text
    



def service_accept_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response,pcap_file_path,dl_com_invoke_line):
    
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    factor_text = service_accept_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    
    if response in possible_response:
        
        status = '--'
        remark = '--'
        
        if (response == 'Deregistration request (UE originating)' ):
            status = 'Pass'
            remark = 'UE gets de-registered from the network, no security issue'  

        elif (response == '5GMM status (Message type not compatible with the protocol state)' ):
            status = 'Pass'
            remark = '5GMM status, no security issue.'  

    else:
        status = 'Inconclusive'
        remark = 'Unusual observation, kindly check!'
        
    return factor_text,status, remark  
    

def service_accept_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line):
    
    
    response = 'No response'
    status = '--'
    remark = '--'
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
  
    factor_text = service_accept_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    status = 'Pass'
    remark =  'UE didn\'t respond, no security issue.'
       
    return factor_text,status, remark,response  