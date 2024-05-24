import subprocess   
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output , chatgpt_response, prompt_creator 


def service_accept_factor_retrieve_text(uplink_command,downlink_command,key_estbl_status,message_encoding_type,pcap_file_path,dl_com_invoke_line):


    pcap_file = pcap_file_path
    

    if key_estbl_status:
        key_estbl_status_str = 'Completed'
    else:
        key_estbl_status_str = 'Not completed'
        

    factor_text = (
        'Uplink message from the UE: ' + convert_to_readable(uplink_command) + '\n' +
        'Downlink command: ' + convert_to_readable(downlink_command) + '\n' +
        '5G-AKA: ' + key_estbl_status_str + '\n' +
        'Message send as: ' + message_encoding_type + '\n' 
    )
    

    return factor_text
    
    
def service_accept_part(factor_to_consider, uplink_command, downlink_command ,response, pcap_file_path,dl_com_invoke_line, renamed_pcap_text):
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]  
    factor_text = service_accept_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    full_prompt = prompt_creator(downlink_command, uplink_command,response,factor_text, renamed_pcap_text)
    chatgpt_answer, status = chatgpt_response(full_prompt)
    return full_prompt,chatgpt_answer, status   