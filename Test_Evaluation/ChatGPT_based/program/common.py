import os
import re
import json
import openai
import subprocess
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter,  landscape
from reportlab.platypus.paragraph import Paragraph
from reportlab.platypus.flowables import KeepInFrame
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, LongTable, TableStyle, Paragraph, KeepTogether, Preformatted
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageTemplate, Frame
from langchain.document_loaders import UnstructuredPDFLoader, OnlinePDFLoader, PyPDFLoader

openai.api_key = "" # Important: openai api key should go here


def convert_to_readable(word):
    return ' '.join(word.split('_'))
    
def table_creator(table_data):

 
    now = datetime.now()
    date_time_text = now.strftime("%Y-%m-%d %H:%M:%S")


    date_time_style = ParagraphStyle(name="DateStyle", fontSize=7, leftIndent=105)
    date_time_paragraph = Paragraph(f"UE Response Evaluation Report: Test time: {date_time_text}", date_time_style)


    pdf_filename = "report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=landscape(letter), leftMargin=0.0, rightMargin=0.0)

    table_style = TableStyle([
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),  
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),  
        ('TOPPADDING', (0, 0), (-1, -1), 3),  
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),  
    ])



    styles = getSampleStyleSheet()
    custom_style = styles["Normal"]
    custom_style.fontSize = 6



    styles3 = getSampleStyleSheet()
    custom_style3 = styles3["Normal"]
    custom_style3.fontSize = 6
    custom_style3.alignment = 1 

    column2 = getSampleStyleSheet()
    column2_style = column2["Normal"]
    column2_style.fontSize = 6
    column2_style.leading = 8
    column2_style.alignment = 1 

    column3 = getSampleStyleSheet()
    column3_style = column3["Normal"]
    column3_style.fontSize = 6
    column3_style.leading = 8

    column5 = getSampleStyleSheet()
    column5_style = column5["Normal"]
    column5_style.fontSize = 6
    column5_style.leading = 8
    
    column6 = getSampleStyleSheet()
    column6_style = column6["Normal"]
    column6_style.fontSize = 6
    column6_style.leading = 8

         
    for row_idx, row in enumerate(table_data):
        for i, cell in enumerate(row):
            if row_idx == 0:  
                row[i] = Paragraph(cell, custom_style3)
            else: 
                if i == 0:
                    row[i] = Paragraph(cell, custom_style)
                elif i == 1:
                    row[i] = Paragraph(cell, column2_style)
                elif i == 2:
                    formatted_content = Preformatted(cell.replace('\t', ' '), column3_style)
                    row[i] = formatted_content
                    #row[i] = Paragraph(cell.replace('\t', ' '), column3_style, maxLineLength=0)  # Use Preformatted for column 3
                elif i == 3:
                    if cell == 'Secure':
                        cell_color = colors.green 
                    elif cell == 'Insecure':
                        cell_color = colors.red 
                    elif cell =='Inconclusive':
                        cell_color = colors.orange
                    else:
                        cell_color = colors.black  
                    column4 = getSampleStyleSheet()
                    column4_style = column4["Normal"]
                    column4_style.fontSize = 6
                    column4_style.textColor = cell_color
                    column4_style.alignment = 1
                    row[i] = Preformatted(cell, column4_style)
                elif i ==4:
                    row[i]= Paragraph(cell, column6_style)

    col_widths = [doc.width / 20, doc.width / 12, doc.width /2, doc.width / 15, doc.width / 6]  
    table = LongTable(table_data, colWidths=col_widths)
    table.setStyle(table_style)

    content = [date_time_paragraph, table]
    doc.build(content)


def test_case_content_retrieve(testcase_file):

    with open(testcase_file, 'r') as file: # to check AKA or post-AKA
        data = json.load(file)

    for index, element in enumerate(data, start=1):
        ue_ul_handle = element["ue_ul_handle"]
        if ue_ul_handle != "null":
        
            testcase_content = element
            keys = list(testcase_content.keys())
            values = list(testcase_content.values())


            if isinstance(values[3], dict):
                dl_params_keys = list(values[3].keys())
                dl_params_values = list(values[3].values())
                
    return dl_params_keys,dl_params_values
    
def ul_dl_command_search(testcase_file_path):

    if os.path.exists(testcase_file_path):
        with open(testcase_file_path, 'r') as file: 
            data = json.load(file)
           
            for index, element in enumerate(data, start=1):
                ue_ul_handle = element["ue_ul_handle"]
                if ue_ul_handle != "null":
                    return element
    else:
        print('Check testcase')
        return None

def extract_file_names(pcap_directory):
    file_names = os.listdir(pcap_directory)
    return sorted(file_names)


def remove_extension(name):
    return name[:-5]  # removing ".pcap" from the file name

def check_paths(file_name,pcap_directory,testcase_directory):
    testcase_file_path = f"{testcase_directory}/{file_name}.json"
    pacp_file_path = f"{pcap_directory}/{file_name}.pcap"
    return os.path.exists(testcase_file_path) and os.path.exists(pacp_file_path), testcase_file_path, pacp_file_path
    
        

def get_ul_dl_index_in_slice(lines, ul_command, dl_command):

    ul_indices = []
    dl_indices = []
    
    dl_command_line = None
    slice_between = None

    lines = lines.strip().split('\n')
    


    for index, line in enumerate(lines):
        if ul_command.lower() in line.lower():
            ul_indices.append(index)
        if dl_command.lower() in line.lower():
            dl_indices.append(index)
            
    if ul_indices and dl_indices:
        end_index = dl_indices[-1]
        result = [value for value in ul_indices if value < end_index]
        if result:
            start_index = result[-1]
            dl_command_line = end_index
            selected_slice = lines[start_index:]  # Slice from start_index to the end
            slice_between = '\n'.join(selected_slice)
            
            #print(selected_slice)

    if slice_between is None and dl_command_line is None:
        return None

    return slice_between, dl_command_line

   
def find_last_uplink_index(my_list, pattern):
    state = 0
    last_uplink_index = None
    
    #print(my_list)

    for index, item in enumerate(my_list):
        if pattern[state] in item:
            state += 1

            if state == len(pattern):
                state = 0
                last_uplink_index = index

    return last_uplink_index
    
     
def response_retrieve(pcap_string,uplink_command,downlink_command): 
    
    lines = pcap_string.splitlines()
    uplink = 'UplinkNASTransport'
    UE_answer = None
    pattern = ['DownlinkNASTransport', 'UEContextReleaseCommand', 'UplinkNASTransport']
    last_uplink_index = find_last_uplink_index(lines, pattern)
    

    if last_uplink_index is not None:
        target_line = lines[last_uplink_index]
        indx = target_line.find(uplink)
        UE_answer = target_line[indx + len(uplink):].strip()
     
    return UE_answer

    
def recorded_response(file_name, pacp_file_path, uplink_command, downlink_command, command):

    ul_command = convert_to_readable(uplink_command)
    dl_command = convert_to_readable(downlink_command)

    desired_words = [ul_command,dl_command]

    try:
  
        output = subprocess.check_output(command, text=True)
        lines = output.strip().split('\n')

        ###### for 0.00 format ########
        first_timestamp_str = lines[0].split('\t')[0]
        if first_timestamp_str:
            try:
                first_timestamp = float(first_timestamp_str)
            except ValueError:
                return None
        else:
            return None


        for index, line in enumerate(lines):
            new_time = str(float(line.split('\t')[0]) - first_timestamp)
            lines[index] = lines[index].replace(line.split('\t')[0], new_time, 1)

        IU_reg_indx = []


        for index, line in enumerate(lines):
            if 'InitialUEMessage, Registration request' in line:
                IU_reg_indx.append(index)

        
        if len(IU_reg_indx) == 0:
            return None

        elif len(IU_reg_indx) == 1:
        
            slice_between = '\n'.join(lines)
            
            slice_lower = slice_between.lower()
            desired_words_lower = [word.lower() for word in desired_words]
            
            if all(word in slice_lower for word in desired_words_lower):
                temp_result = get_ul_dl_index_in_slice(slice_between, ul_command, dl_command)
                if temp_result is not None:
                    result,dl_com_invoke_line = temp_result
                    slice_start = IU_reg_indx[0]
                    return result , IU_reg_indx,slice_start,dl_com_invoke_line
            else:
                return None

        elif len(IU_reg_indx) > 1:
        
            flag = False
            for m in range(len(IU_reg_indx) - 1):
                slice_between = '\n'.join(lines[IU_reg_indx[m]:IU_reg_indx[m + 1]])
                slice_lower = slice_between.lower()
                desired_words_lower = [word.lower() for word in desired_words]
                
                if all(word in slice_lower for word in desired_words_lower):
                    flag = True
                    temp_result = get_ul_dl_index_in_slice(slice_between, ul_command, dl_command)
                    if temp_result is not None:
                        result,dl_com_invoke_line = temp_result
                        slice_start = IU_reg_indx[m]
                        dl_com_invoke_line = slice_start + dl_com_invoke_line
                        return result , IU_reg_indx,slice_start, dl_com_invoke_line
            else:
                
                last_index = IU_reg_indx[-1]
                slice_between = '\n'.join(lines[IU_reg_indx[-1]:])
                slice_lower = slice_between.lower()
                desired_words_lower = [word.lower() for word in desired_words]
                if all(word in slice_lower for word in desired_words_lower):
                    flag = True
                    temp_result = get_ul_dl_index_in_slice(slice_between, ul_command, dl_command)
                    if temp_result is not None:
                        result,dl_com_invoke_line = temp_result
                        print(type(result))
                        slice_start = IU_reg_indx[-1]
                        dl_com_invoke_line = slice_start + dl_com_invoke_line
                        return result , IU_reg_indx,slice_start, dl_com_invoke_line

            if not flag:
                return None

    except subprocess.CalledProcessError as e:
        return None

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
    
def cipher_algorithm_mapping_name(cipher_algorithm):
    
    if cipher_algorithm == 0:
        name = '5G-EA0 (null)'
    elif cipher_algorithm == 1:
        name = '128-5G-EA1'
    elif cipher_algorithm == 2:
        name = '128-5G-EA2'
    elif cipher_algorithm == 3:
        name = '128-5G-EA3'
    elif cipher_algorithm == 4:
        name = '5G-EA4'
    elif cipher_algorithm == 5:
        name = '5G-EA5'
    elif cipher_algorithm == 6:
        name = '5G-EA6'
    elif cipher_algorithm == 7:
        name = '5G-EA7'
    else:
        name = 'Unknown Cipher Algorithm'
    
    return name
        
def integrity_algorithm_mapping_name(integrity_algorithm):
    
    if integrity_algorithm == 0:
        name = '5G- IA0 (null)'
    elif integrity_algorithm == 1:
        name = '128-5G-IA1'
    elif integrity_algorithm == 2:
        name = '128-5G-IA2'
    elif integrity_algorithm == 3:
        name = '128-5G-IA3'
    elif integrity_algorithm == 4:
        name = '5G-IA4'
    elif integrity_algorithm == 5:
        name = '5G-IA5'
    elif integrity_algorithm == 6:
        name = '5G-IA6'
    elif integrity_algorithm == 7:
        name = '5G-IA7'
    else:
        name = 'Unknown Integrity Algorithm'
    
    return name    
    
    
    
def identity_mapping_name(requested_identity):
    
    if requested_identity == 0:
        name = 'SUCI'
    elif requested_identity == 1:
        name = 'SUCI'
    elif requested_identity == 2:
        name = 'GUTI'
    elif requested_identity == 3:
        name = 'IMEI'
    elif requested_identity == 4:
        name = 'TMSI'
    elif requested_identity == 5:
        name = 'IMEISV'
    else:
        name = 'Unknown Identity'
    
    return name    
    
    
    

def get_tshark_output(pcap_file, field_name, dl_com_invoke_line):
    try:
        line_number = int(dl_com_invoke_line)  + 1  # for solving start from 0
        command = f"tshark -r {pcap_file} -T fields -e {field_name} | awk 'NR=={line_number}'"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        process.terminate()

        if process.returncode == 0:
            output = stdout.strip()
            return output
        else:
            print("Error executing command:", stderr)
            return None
    except Exception as e:
        print("An error occurred:", str(e))
        return None 
    
    
    
def handle_response(pattern, ue_response):
    if ue_response == ', UL NAS transport, PDU session establishment request':
        return 'PDU session establishment request'
    elif ue_response == ', Security mode reject (Security mode rejected, unspecified)':
        return 'Security mode reject (Security mode rejected, unspecified)'
    elif ue_response == ', Security mode reject (Security mode rejected, unspecified), UplinkNASTransport, Deregistration request (UE originating)':
        return 'Security mode reject (Security mode rejected, unspecified)'
    else:
        match = re.search(pattern, ue_response)
        if match:
            return match.group(1).strip()
        else:
            return ue_response.strip(', ')
            



def message_security_type(dl_params_keys, dl_params_values, downlink_command):
    dl_com = downlink_command.lower()

    protected_commands = [
        'security_mode_command',
        'configuration_update_command',
        'deregistration_request',
        'deregistration_accept',
        'gmm_status',
        'service_accept',
        'registration_accept',
        'authentication_result'
    ]

    security_type = 'Protected' if dl_com in protected_commands else 'Plain'

    if security_type == 'Protected':
        key = f'{dl_com}_security'
        if key in dl_params_keys:
            index = dl_params_keys.index(key)
            value = dl_params_values[index]

            if value == 'disabled':
                security_type = 'Plain'

    return security_type


def security_header_mapping_name(header_type):
    try:
        header = int(header_type)
    except ValueError:
        return None
    
    name = None
    
    if header == 0:
        name = 'Plain NAS message (0)'
    elif header == 1:
        name = 'Integrity protected (1)'
    elif header == 2:
        name = 'Integrity protected and ciphered (2)'
    elif header == 3:
        name = 'Integrity protected with new security context (3)'
    elif header == 4:
        name = 'Integrity protected and ciphered with new security context (4)'
    else:
        name = 'Unknown'
    
    return name



def chatgpt_response(full_prompt):
    chatgpt_answer = ' '  
    status = '-- '
    explanation = ' '
    
    message=[{"role": "user", "content": full_prompt}]
    response = openai.ChatCompletion.create(
        model="gpt-4",#"gpt-4",
        max_tokens=500,
        temperature=0.5,
        messages = message
    )
    
    # Access the "content" field inside the "message" within the "choices" array
    chatgpt_answer = response.choices[0].message.content
    
    print('\n ### Answer ### \n')
    print(chatgpt_answer)

    secure_index = chatgpt_answer.lower().find('secure')
    insecure_index = chatgpt_answer.lower().find('insecure')
    inconclusive_index = chatgpt_answer.lower().find('inconclusive')

    # Check which occurs first and set the status accordingly
    if secure_index != -1 and ((insecure_index == -1 or secure_index < insecure_index) and (inconclusive_index == -1 or secure_index < inconclusive_index)):
        status = 'Secure'
    elif insecure_index != -1 and ((secure_index == -1 or insecure_index < secure_index) and (inconclusive_index == -1 or insecure_index < inconclusive_index)):
        status = 'Insecure'
    elif inconclusive_index != -1 and ((secure_index == -1 or inconclusive_index < secure_index) and (insecure_index == -1 or inconclusive_index < insecure_index)):
        status = 'Inconclusive'
    else:
        status = 'Not answered'
    
    return chatgpt_answer, status


def prompt_creator(downlink_command, uplink_command,response,factor_text, renamed_pcap_text):

    line0 = 'This is a security test for an UE. The UE sent ' + convert_to_readable(uplink_command) + ' then \n' 
    line1 = 'The AMF sent ' + convert_to_readable(downlink_command) + ' to UE. The test summary as follows: \n \n'
    line2 = factor_text
    line3 = 'UE provided: ' + response +'\n'
    line4 = '\nThe packet capture during the test using wireshark is: \n'
    line5 =  renamed_pcap_text +'\n'
    line6 = '\nWas the UE behavior secure? Compare what the UE should have done with what UE actually did? \nYou must mention section or page numbers in your reasoning. \nAnd you must include the reason for your decision in more than 50 words. \nFirst, state whether the behavior was secure or insecure, followed by a full stop. Then provide the reason to support your decision. ' 
    full_prompt = line0 + line1 + line2  + line3 + line4 + line5 + line6
    
    return full_prompt




def replace_ue_core(pcap_print):
    rows = pcap_print.strip().split('\n')
    for i, row in enumerate(rows):
    
        row_data = row.split('\n')
        
        UEContextReleaseCommand_index = row_data[0].find("UEContextReleaseCommand")
        UEContextReleaseComplete_index = row_data[0].find("UEContextReleaseComplete")
        InitialContextSetupRequest_index = row_data[0].find("InitialContextSetupRequest")
        InitialContextSetupResponse_index = row_data[0].find("InitialContextSetupResponse")

        ue_index = row_data[0].find("127.0.1.1")
        core_index = row_data[0].find("127.0.0.5")

        if ue_index < core_index and UEContextReleaseCommand_index == -1 and UEContextReleaseComplete_index == -1 and InitialContextSetupRequest_index == -1 and InitialContextSetupResponse_index == -1:
            output_string = row_data[0].replace("127.0.1.1", "UE to ").replace("127.0.0.5", "Core")
            rows[i] = output_string
        elif core_index < ue_index and (UEContextReleaseCommand_index != -1 or InitialContextSetupRequest_index != -1):
            output_string = row_data[0].replace("127.0.0.5", "Core to ").replace("127.0.1.1", "gNB")
            rows[i] = output_string
        elif core_index > ue_index and (UEContextReleaseComplete_index != -1 or InitialContextSetupResponse_index != -1):
            output_string = row_data[0].replace("127.0.1.1", "gNB to ").replace("127.0.0.5", "Core")
            rows[i] = output_string
        elif ue_index > core_index and UEContextReleaseCommand_index == -1 and UEContextReleaseComplete_index == -1 and InitialContextSetupRequest_index == -1 and InitialContextSetupResponse_index == -1:
            output_string = row_data[0].replace("127.0.0.5", "Core to ").replace("127.0.1.1", "UE ")
            rows[i] = output_string

    new_content_string = '\n'.join(rows)
    return new_content_string
