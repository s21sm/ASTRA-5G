# ASTRA-5G

## Table of Contents
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Reference](#reference)

## Description
This project contains souce codes and installation guide for **ASTRA-5G: Automated Over-the-Air Security Testing and Research Architecture for 5G SA Devices**

## Installation

### Testcase Generator
prerequisite for testcase generator: Python 3.x tkinter subprocess32 platformdirs 

Testcase generator
```
git clone https://github.com/your-username/5G-UE-test-suite-generator.git
cd 5G-UE-test-suite-generator
python3 GUI_dispatcher.py
```
More installation information are available at [link](https://github.com/MicheleGuerra/5G-UE-Test-suite-generator)

### Test Execution

prerequisite for open5gs:  apt install python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison git cmake libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson libjson0 libjson0-dev

prerequisite for srsRAN:  sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev

```
git colne https://github.com/s21sm/5G-UE-SecurityTesting.git
```
It contains modified open5gs and srsRAN software. Which can be installed as follows:

open5gs
```
cd open5gs
meson build --prefix=`pwd`/install
ninja -C build
cd build
ninja install
```
More installation information are available at open5gs official [site](https://open5gs.org/open5gs/docs/guide/02-building-open5gs-from-sources) and [link](https://github.com/vaggelis-sudo/5G-UE-SecurityTesting) 

srsRAN
```
cd srsRAN    
mkdir build    
cd build
cmake ../
make
sudo make install
```
More installation information are available at srsRAN offcial [site](https://docs.srsran.com/projects/4g/en/latest/general/source/1_installation.html) and [link](https://github.com/vaggelis-sudo/5G-UE-SecurityTesting) 

### Test Evaluation
```
git colne https://github.com/s21sm/5G-UE-SecurityTesting.git
cd rule-based
python3 main.py 
```
This repository contains the rule-based and ChatGPT based test case evaluation code. Which has been tested with Wireshark v4.0.6. A valid openai api key is required for ChatGPT based evaluation. In Wiresark, Eidt>>Preferences>>Protocols>>NAS-5GS check mark <br> `Try to detect and decode 5G-EA0 ciphered message` .

## Usage
Step 1: Use Test case generator to produce test cases according to the preference. <br> 
Step 2: Place the test cases in the Test_nas folder. <br>
Step 3: Run the test and collect the pcap files. More information on how to run the NAS test [link](https://github.com/vaggelis-sudo/5G-UE-SecurityTesting)   <br>
Step 4: Put the test case and pcap files in the Test_nas and pcap folder, repectively in the prefered evaluation method folder. <br>
Step 5: Run main.py of any evaluation method to produce the evaluation report. <br>

## License
The **ASTRA-5G** project is open-source.

## Reference
If you are using or referencing this project, please cite the following paper:
<blockquote style="background-color: #f7f7f7; padding: 10px; border-left: 6px solid #1f618d;">
<pre>
@inproceedings{bitsikas23UEframework,
  <span style="color: #c0392b;">title = {ASTRA-5G: Automated Over-the-Air Security Testing and Research Architecture for 5G SA Devices},</span>
  <span style="color: #2980b9;">author = {Khandker, Syed and Guerra, Michele and Bitsikas, Evangelos and Piqueras Jover, Roger and Ranganathan, Aanjhan and Pöpper, Christina},</span>
  <span style="color: #27ae60;">booktitle = {Proceedings of the 17th ACM Conference on Security and Privacy in Wireless and Mobile Networks},</span>
  <span style="color: #8e44ad;">year = {2023},</span>
  <span style="color: #e67e22;">url = {https://doi.org/10.1145/3643833.3656141}</span>
}
</pre>
</blockquote>
