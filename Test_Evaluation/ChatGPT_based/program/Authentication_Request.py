import re
from program.common import convert_to_readable , cipher_algorithm_mapping_name, integrity_algorithm_mapping_name, get_tshark_output, chatgpt_response, prompt_creator 


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
    
    if abba is not None and abba.strip():
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

    return factor_text
    

def authntication_request_part(factor_to_consider, uplink_command, downlink_command ,response, pcap_file_path,dl_com_invoke_line, renamed_pcap_text):
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]  
    factor_text = authentication_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    full_prompt = prompt_creator(downlink_command, uplink_command,response,factor_text, renamed_pcap_text)
    chatgpt_answer, status = chatgpt_response(full_prompt)
    return full_prompt,chatgpt_answer, status   
