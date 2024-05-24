import os
import re  
import json
from program import Identity_Request, Authentication_Request, Security_Mode_Command, Configuration_Update_Command, Deregistration_Request, Service_Accept, Service_Reject,Gmm_Status, Deregistration_Accept, Authentication_Reject, Registration_Reject, common

def process_files(file_name,testcase_file_path,pcap_directory, testcase_directory):

    key_estbl_status = False
    factor_to_consider = []


    uplink_list = ['registration_request', 'identity_response', 'authentication_response', 'security_mode_complete', 'registration_complete', 'ul_nas_transport',
                   'security_mode_reject', 'authentication_failure', 'service_request', 'gmm_status', 'configuration_update_complete', 'deregistration_request', 'deregistration_accept', 'timer']

    downlink_list = ['identity_request', 'authentication_request', 'security_mode_command', 'registration_accept', 'configuration_update_command', 'service_accept',
                     'service_reject', 'gmm_status', 'deregistration_accept', 'deregistration_request', 'authentication_result', 'authentication_reject', 'registration_reject']

    try:
        
        ul_dl_command = common.ul_dl_command_search(testcase_file_path)  # Call function to fetch ul_dl_commands

        if ul_dl_command is not None:
            values = list(ul_dl_command.values())
            uplink_command = values[0]
            downlink_command = values[1]
            dl_params_keys,dl_params_values = common.test_case_content_retrieve(testcase_file_path)


            if uplink_command in uplink_list and downlink_command in downlink_list:
                uplink_position = uplink_list.index(uplink_command) + 1
                downlink_position = downlink_list.index(downlink_command) + 1
                possible_response = common.response_list_finder(uplink_position, downlink_position)  # Use function to find possible response
                if uplink_position >= 4:
                    key_estbl_status = True
                  
                if  (downlink_command.lower() == 'identity_request'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'authentication_request'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)   
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'security_mode_command'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'configuration_update_command'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'deregistration_request'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                   
                elif  (downlink_command.lower() == 'service_accept'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'service_reject'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                
                elif  (downlink_command.lower() == 'gmm_status'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'deregistration_accept'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'authentication_reject'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                elif  (downlink_command.lower() == 'registration_reject'):
                    message_security = common.message_security_type(dl_params_keys,dl_params_values, downlink_command)                    
                    factor_to_consider = [key_estbl_status, message_security]
                    
                if len(possible_response) != 0:
                    return uplink_command,downlink_command,possible_response,factor_to_consider
                else:
                    raise ValueError("No prior information found for this experiment")
            else:
                raise ValueError("Uplink or downlink command not found in the testcase " + file_name + " kindly recheck")
        else:
            raise ValueError("Encountered a problem with uplink / downlink command in "+ file_name + " kindly check")
    except Exception as e:
        print(f"Error occurred: {e}")
        return None
        

def main(pcap_directory,testcase_directory):

    table_data = [["SL","Test Name", 'Test content' ,"UE response", "Status", "Remark"]]
    
    sorted_file_names = common.extract_file_names(pcap_directory)

    for index, name in enumerate(sorted_file_names, start=1):  # start=1 to make the index 1-based
    
        factor_text = '--'
        response = '--'
        status  = '-- '
        remark = '--'
        factor_to_consider = []
        pattern = r',\s*([^,]+)' #r'\b([^,(]+ \([^)]*\))\b'  #r'\b([^,(]+(?:\([^)]*\))?)\b'  # r'\b([^,]+)\b'
        
        file_name = common.remove_extension(name)

        path_exists, testcase_file_path, pcap_file_path = common.check_paths(file_name, pcap_directory, testcase_directory)
        
        

        if path_exists:
            uplink_command, downlink_command, possible_response,factor_to_consider= process_files(file_name, testcase_file_path,pcap_directory, testcase_directory)
            result = common.recorded_response(file_name, pcap_file_path, uplink_command, downlink_command)
            if result is not None:
                extracted_slice, IU_reg_indx,slice_start,dl_com_invoke_line = result
                print('Evaluating', f'### {file_name} ###')
                ue_response = common.response_retrieve(extracted_slice,uplink_command,downlink_command)
                if ue_response is not None:

                    if  (downlink_command.lower() == 'identity_request'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Identity_Request.identity_request_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'authentication_request'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Authentication_Request.authntication_request_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                    
                    elif  (downlink_command.lower() == 'security_mode_command'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Security_Mode_Command.security_mode_command_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'configuration_update_command'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Configuration_Update_Command.configuration_update_command_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                        
                    elif  (downlink_command.lower() == 'deregistration_request'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Deregistration_Request.deregistration_request_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                    
                    elif  (downlink_command.lower() == 'service_accept'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Service_Accept.service_accept_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                        
                    elif  (downlink_command.lower() == 'service_reject'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Service_Reject.service_reject_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)

                    elif  (downlink_command.lower() == 'gmm_status'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Gmm_Status.gmm_status_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                    
                    elif  (downlink_command.lower() == 'deregistration_accept'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Deregistration_Accept.deregistration_accept_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                        
                    elif  (downlink_command.lower() == 'authentication_reject'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Authentication_Reject.authentication_reject_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)
                        
                        
                    elif  (downlink_command.lower() == 'registration_reject'):
                        response = common.handle_response(pattern,ue_response)
                        factor_text,status, remark = Registration_Reject.registration_reject_if_part(factor_to_consider, uplink_command, downlink_command, response, possible_response, pcap_file_path,dl_com_invoke_line)

                else: ## For no response
                
                    if  (downlink_command.lower() == 'identity_request'):
                        factor_text, status, remark,response  = Identity_Request.identity_request_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line)
                    
                    elif  (downlink_command.lower() == 'authentication_request'):
                        factor_text, status, remark,response  = Authentication_Request.authntication_request_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'security_mode_command'):
                        factor_text, status, remark,response  = Security_Mode_Command.security_mode_command_else_part(factor_to_consider, uplink_command, downlink_command,pcap_file_path,dl_com_invoke_line) 
                        
                    elif  (downlink_command.lower() == 'configuration_update_command'):
                        factor_text,status, remark,response = Configuration_Update_Command.configuration_update_command_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'deregistration_request'):
                        factor_text,status, remark,response = Deregistration_Request.deregistration_request_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'service_accept'):
                        factor_text,status, remark,response = Service_Accept.service_accept_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'service_reject'):
                        factor_text,status, remark,response = Service_Reject.service_reject_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'gmm_status'):
                        factor_text,status, remark,response = Gmm_Status.gmm_status_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'deregistration_accept'):
                        factor_text,status, remark,response = Deregistration_Accept.deregistration_accept_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'authentication_reject'):
                        factor_text,status, remark,response = Authentication_Reject.authentication_reject_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
                        
                    elif  (downlink_command.lower() == 'registration_reject'):
                        factor_text,status, remark,response = Registration_Reject.registration_reject_else_part(factor_to_consider, uplink_command, downlink_command, pcap_file_path,dl_com_invoke_line)
            else:
                response    = '--'
                status = '--'
                remark = f"{file_name} pacp has insufficient data or uplink or downlink command is missing in the capture"
            
            table_data.append([str(index),file_name, factor_text,response,status,remark])  
            

    
    common.table_creator(table_data)



if __name__ == "__main__":

    pcap_directory = './pcap'   # Give pcap files directory
    testcase_directory = './Test_nas'   # Give testcase files directory
    main(pcap_directory,testcase_directory)
