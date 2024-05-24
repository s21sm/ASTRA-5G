import subprocess   
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output, security_header_mapping_name

def deregistration_request_factor_retrieve_text(uplink_command,downlink_command,key_estbl_status,message_encoding_type,pcap_file_path,dl_com_invoke_line):


    pcap_file = pcap_file_path
    
    security_header_field = 'nas_5gs.security_header_type'
    
    header = get_tshark_output(pcap_file, security_header_field, dl_com_invoke_line)

    first_part = None  # Initialize first_part outside the if statement

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

    if header is not None and header.strip():
        parts = header.split(',') 

        if parts:  # Check if parts is not empty before accessing its elements
            first_part = parts[0]
            
            name = security_header_mapping_name(str(first_part))

            factor_text += 'Security header: ' + name+ '\n'


    return factor_text,str(first_part)
    



def deregistration_request_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response,pcap_file_path,dl_com_invoke_line):
    
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    factor_text,security_header_type = deregistration_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    
    if response in possible_response:
        
        status = '--'
        remark = '--'
               
        if (response == 'Deregistration request (UE originating)' ):
            status = 'Pass'
            remark = 'UE gets de-registered from the network, no security issue'  
            
        elif (response == '5GMM status (Invalid mandatory information)' ):
            status = 'Pass'
            remark = '5GMM status, no security issue.'  

        elif (response == 'Deregistration accept (UE terminated)' ):
            
            if (key_estbl_status == True and message_encoding_type == 'Protected'  and security_header_type != '0' ):
                status = 'Pass'
                remark = 'UE accepted deregistration requested after AKA completed.'
                
            elif (key_estbl_status == False):
                status = 'Fail'
                remark = 'Deregistration request should not be accepted before registration completed'
            
            elif (message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'Plain Deregistration request  should not be processed'
                
            elif (security_header_type == '0'):
                status = 'Fail'
                remark = 'Plain NAS security header type accepted' 
            
            
            
        
    else:
        status = 'Inconclusive'
        remark = 'Unusual observation, kindly check!'
        
    return factor_text,status, remark  
    

def deregistration_request_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line):
    
    
    response = 'No response'
    status = '--'
    remark = '--'
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
  
    factor_text , security_header_type= deregistration_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    status = 'Pass'
    remark =  'UE didn\'t respond, no security issue.'
       
    return factor_text,status, remark,response  
