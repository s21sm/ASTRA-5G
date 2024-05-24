import re
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output 


def authentication_request_factor_retrieve_text(uplink_command,downlink_command,key_estbl_status,message_encoding_type,pcap_file_path,dl_com_invoke_line):

    pcap_file = pcap_file_path
    
    abba_field = 'nas_5gs.mm.abba_contents'
    rand_field = 'gsm_a.dtap.rand'
    autn_field = 'gsm_a.dtap.autn'
    tsc_field= 'nas_5gs.mm.tsc'
    ksi_field = 'nas_5gs.mm.nas_key_set_id'
    
    abba = get_tshark_output(pcap_file, abba_field, dl_com_invoke_line)
    rand = get_tshark_output(pcap_file, rand_field, dl_com_invoke_line)
    autn = get_tshark_output(pcap_file, autn_field, dl_com_invoke_line)
    ngksi_tsc = get_tshark_output(pcap_file, tsc_field, dl_com_invoke_line)
    ngksi_ksi = get_tshark_output(pcap_file, ksi_field, dl_com_invoke_line)
    
    abba_value = 'dummy'

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
    
    if abba is not None and abba.strip():
        abba_value =  str(abba) 
        factor_text += 'ABBA: ' + str(abba) + '\n'

    if rand is not None and rand.strip():
        rand_value = str(rand)
        factor_text += 'RAND: ' + rand_value + '\n'
        
    if autn is not None and autn.strip():
        autn_value = str(autn)
        factor_text += 'AUTN: ' + autn_value + '\n'
        
    if ngksi_tsc is not None and ngksi_tsc.strip():
        ngksi_tsc_value = str(ngksi_tsc)
        factor_text += 'ngKSI_TSC: ' + ngksi_tsc_value + '\n'
    
    if ngksi_ksi is not None and ngksi_ksi.strip():
        ngksi_ksi_value = str(ngksi_ksi)
        factor_text += 'ngKSI_KSI: ' + ngksi_ksi_value + '\n'

    return factor_text, abba_value
    
    
   
    
def authntication_request_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line):
    
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    factor_text, abba_value = authentication_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    if response in possible_response:
        status = '--'
        remark = '--'
    
        if response == 'Authentication failure (ngKSI already in use)':
            
            if (key_estbl_status == False and message_encoding_type == 'Plain'):
                status = 'Pass'
                remark = 'The ngKSI value received in the authentication request is already associated with one of the 5G security contexts stored in the UE'
            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
                    

        elif response == 'Authentication failure (Non-5G authentication unacceptable)':
            
            if (key_estbl_status == False and message_encoding_type == 'Plain'):
                status = 'Pass'
                remark = 'In AUTN, the Authentication Management Field (AMF) value is invalid. Valid AMF values are e.g., 8000, 9000 etc. '    
            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'

        elif response == '5GMM status (Invalid mandatory information)':
            status = 'Pass'
            remark = 'UE has received a message with a non-semantical mandatory information element error'    
            
        elif response == 'Deregistration request (UE originating)':
            status = 'Pass'
            remark = 'UE gets de-registered from the network, no security issue'  
            
        elif response == 'Authentication failure (MAC failure)':
            if (key_estbl_status == False and message_encoding_type == 'Plain' ):
                status = 'Pass'
                remark = 'MAC failure'
            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
            
        elif response == 'Authentication failure (Synch failure)':
            
            if (key_estbl_status == False and message_encoding_type == 'Plain' ):
                status = 'Pass'
                remark = 'SQN value out of range, 5GMM cause 21'
            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'
            
        elif response == 'Authentication response':
            
            if (key_estbl_status == False and message_encoding_type == 'Plain'): 
            
                if abba_value == '0000':
                    status = 'Pass'
                    remark = 'Valid Authentication response' 

                elif abba_value == 'dummy':
                    status = 'Inconclusive'
                    remark = 'ABBA not found' 

                elif abba_value != '0000' and abba_value != 'dummy':
                    status = 'Inconclusive'
                    remark = 'ABBA value is not 0000, however, UE accepted that' 
                    
            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should not be processed'

    else:
        status = 'Inconclusive'
        remark = 'Unusual observation, kindly check!'
        
    return factor_text,status, remark  
     

def authntication_request_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line):
    
    response = 'No response'
    status = '--'
    remark = '--'
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
  
    factor_text,abba_value = authentication_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    status = 'Pass'
    remark =  'UE didn\'t respond, no security issue.'
    
    return factor_text,status, remark,response  