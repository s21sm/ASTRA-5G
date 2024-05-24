from program.common import convert_to_readable, get_tshark_output,identity_mapping_name

      
        
def identity_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line):

    pcap_file = pcap_file_path
    
    identity_field = 'nas_5gs.mm.type_id' 
    requested_identity = get_tshark_output(pcap_file, identity_field, dl_com_invoke_line)


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
    
    requested_identity_name = None
    
    if requested_identity is not None and requested_identity.strip():
        requested_identity_name = identity_mapping_name(int(requested_identity))
        factor_text += 'Requested identity: ' + str(requested_identity_name) + '\n'

    return factor_text, str(requested_identity_name)
    
    
def identity_request_if_part(factor_to_consider, uplink_command, downlink_command ,response, possible_response, pcap_file_path,dl_com_invoke_line):


    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    
    
    factor_text,requested_identity = identity_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)


    if response in possible_response:

        status = '--'
        remark = '--'
        
        if response == 'Identity response':
           
            if (key_estbl_status == False and (requested_identity == 'SUCI' or requested_identity == 'No identity') and message_encoding_type == 'Plain' ):
                status = 'Pass'
                remark = 'Identity type: SUCI'

            elif (key_estbl_status == False and (requested_identity != 'SUCI' or requested_identity != 'No identity') and message_encoding_type == 'Plain' ):
                status = 'Fail'
                remark = 'UE shouldn\'t  give an identity response for ' + requested_identity + 'before AKA complete'

            elif (key_estbl_status == True and message_encoding_type == 'Plain'):
                status = 'Fail'
                remark = 'After key establishment, plain message should be not be processed'    
                
        elif response == 'Deregistration request (UE originating)':
            status = 'Pass'
            remark = 'UE gets de-registered from the network, no security issue'  
        
    
                        
            
    else:
        status = 'Inconclusive'
        remark = 'Unusual observation, kindly check!'
    
    return factor_text,status, remark
 
def identity_request_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line):


    response = 'No response'
    status = '--'
    remark = '--'
    key_estbl_status = factor_to_consider[0]
    message_encoding_type = factor_to_consider[1]
    
    factor_text,requested_identity = identity_request_factor_retrieve_text(uplink_command, downlink_command, key_estbl_status, message_encoding_type,pcap_file_path,dl_com_invoke_line)
    
    
    if (key_estbl_status == False and (requested_identity == 'SUCI' or requested_identity == 'No identity') and message_encoding_type == 'Plain'):
        status = 'Pass'
        remark = 'UE didn\'t respond, no security issue.'

    elif (key_estbl_status == False and (requested_identity != 'SUCI' or requested_identity != 'No identity') and message_encoding_type == 'Plain'):
        status = 'Pass'
        remark = 'Discarded, because of requested identity type: ' + requested_identity + ' which should not be given for plain message or before 5G-AKA complete'

    elif (key_estbl_status == True and message_encoding_type == 'Plain'):
        status = 'Pass'
        remark = 'After key establishment, plain message should be discarded'
        
    return factor_text, status, remark, response