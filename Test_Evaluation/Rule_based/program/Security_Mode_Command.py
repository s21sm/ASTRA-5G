import re
import subprocess   
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output ,security_header_mapping_name

def security_mode_command_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type, pcap_file_path, dl_com_invoke_line):
    pcap_file = pcap_file_path
    
    abba_field = 'nas_5gs.mm.abba_contents'
    cipher_algorithm_field = 'nas_5gs.mm.nas_sec_algo_enc'
    integrity_algorithm_field = 'nas_5gs.mm.nas_sec_algo_ip'
    security_header_field = 'nas_5gs.security_header_type'
    
    abba = get_tshark_output(pcap_file, abba_field, dl_com_invoke_line)
    cipher_algorithm = get_tshark_output(pcap_file, cipher_algorithm_field, dl_com_invoke_line)
    integrity_algorithm = get_tshark_output(pcap_file, integrity_algorithm_field, dl_com_invoke_line)
    header = get_tshark_output(pcap_file, security_header_field, dl_com_invoke_line)
    
    
    abba_value = 'dummy'
    cipher_algorithm_value = 'dummy'
    integrity_algorithm_value = 'dummy'
    header_value = 'dummy'
    
    first_part = None  # Initialize first_part outside the if statement

    if key_estbl_status:
        key_estbl_status_str = 'Completed'
    else:
        key_estbl_status_str = 'Not completed'

    factor_text = (
        'Hooking point: ' + convert_to_readable(uplink_command) + '\n' +
        'Downlink command: ' + convert_to_readable(downlink_command) + '\n' +
        '5G-AKA: ' + key_estbl_status_str + '\n' +
        'Message send as: ' + message_encoding_type + '\n'
    )
    
    if abba is not None and abba.strip():
        abba_value =  str(abba) 
        factor_text += 'ABBA: ' + str(abba) + '\n'

    if cipher_algorithm is not None and cipher_algorithm.strip():
        cipher_algorithm_value = str(cipher_algorithm)
        cipher_algorithm_name = cipher_algorithm_mapping_name(int(cipher_algorithm))
        factor_text += 'Cipher Algorithm: ' + cipher_algorithm_name + '\n'

    if integrity_algorithm is not None and integrity_algorithm.strip():
        integrity_algorithm_value =  str(integrity_algorithm)
        integrity_algorithm_name = integrity_algorithm_mapping_name(int(integrity_algorithm))
        factor_text += 'Integrity Algorithm: ' + integrity_algorithm_name + '\n'
        
    if header is not None and header.strip():
        parts = header.split(',')

        if parts:
            first_part = parts[0]
            header_value = str(first_part)
            name = security_header_mapping_name(str(first_part))
            factor_text += 'Security header: ' + name + '\n'

    return factor_text, abba_value, cipher_algorithm_value, integrity_algorithm_value, header_value



def security_mode_command_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response,pcap_file_path,dl_com_invoke_line):
    
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    factor_text, abba_value, cipher_algorithm_value, integrity_algorithm_value, header_value = security_mode_command_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
       
    if response in possible_response:
        
        status = '--'
        remark = '--'

        if response == 'Security mode reject (Security mode rejected, unspecified)':
            
            if message_encoding_type == 'Protected':
                status = 'Pass'
                remark = 'Security mode command is rejected by the UE for unspecified reasons'
            
            elif key_estbl_status == False and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'Plain Security Mode Command message should not be processed'
                
            elif key_estbl_status == True and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
                
                
        elif response == '5GMM status (Invalid mandatory information)':
            status = 'Pass'
            remark = 'UE has received a message with a non-semantical mandatory information element error'    
            
            
        elif response == 'Security mode reject (UE security capabilities mismatch)':
            
            if message_encoding_type == 'Protected':
                status = 'Pass'
                remark =  'UE security capability does not match the one sent back by the network'  
            
            elif key_estbl_status == False and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'Plain Security Mode Command message should not be processed'
                
            elif key_estbl_status == True and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
            
            
        elif response == 'Deregistration request (UE originating)':
            status = 'Pass'
            remark = 'UE gets de-registered from the network, no security issue'  
            
                
        elif response == 'Security mode complete':
            
            if key_estbl_status == True and message_encoding_type == 'Protected':
                
                if header_value != '0' and integrity_algorithm_value != '0' and  abba_value == '0000':
                    status = 'Pass'
                    remark = 'Security mode completed'  
                    
                elif header_value == '0':
                    status = 'Fail'
                    remark = 'Incorrect security header type' 
                    
                elif integrity_algorithm_value == '0':
                    status = 'Fail'
                    remark = 'Null integrity algorithm '
                    
                elif abba_value == 'dummy':
                    status = 'Inconclusive'
                    remark = 'ABBA not found' 
                    
                elif abba_value != '0000' and abba_value != 'dummy':
                    status = 'Inconclusive'
                    remark = 'ABBA value is not 0000, however, UE accepted that'                     
                
                
            elif key_estbl_status == False and message_encoding_type == 'Protected':
                status = 'Fail'
                remark = 'Before key establishment protected message can not be processed '

            elif key_estbl_status == True and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
                
            elif key_estbl_status == False and message_encoding_type == 'Plain':
                status = 'Fail'
                remark = 'Plain Security Mode Command message should not be processed'

    else:
        status = 'Inconclusive'
        remark = 'Unusual observation, kindly check!'
        
    return factor_text,status, remark  
    

def security_mode_command_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line):

    
    response = 'No response'
    status = '--'
    remark = '--'
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    
    factor_text, abba_value, cipher_algorithm_value, integrity_algorithm_value, header_value= security_mode_command_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
               
    status = 'Pass'
    remark =  'UE didn\'t respond, no security issue.'
       
    return factor_text,status, remark,response  