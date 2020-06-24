#!/usr/bin/python3

from __future__ import print_function, unicode_literals
import json
import os
import sys
from PyInquirer import style_from_dict, Token, prompt
from PyInquirer import Validator, ValidationError
from pyfiglet import Figlet
from termcolor import colored

style = style_from_dict({
    Token.QuestionMark: '#E91E63 bold',
    Token.Selected: '#673AB7 bold',
    Token.Instruction: '',  # default
    Token.Answer: '#2196f3 bold',
    Token.Question: '',
})

default_firmware_version = ''
default_manufacturer = ''
default_model_number = ''
default_marketing_name = ''
default_manufacturer_code = ''

class DataValidator(Validator):
    def validate(self, document):
        if not document.text:
            raise ValidationError(
                message='Please enter the device information (mandatory item)',
                cursor_position=len(document.text))  # Move cursor to end

def askProductInformation():
	optional = colored('[optional]', 'green')

	questions = [
	    {
		'type': 'input',
		'name': 'firmwareVersion',
		'message': '[optional] What is Firmware version?',
		'default' : default_firmware_version
	    },
	    {
		'type': 'input',
		'name': 'manufacturerName',
		'message': '[mandatory] What is Manufacturer name? (e.g. SmartThings, Samsung, Samjin)',
		'validate': DataValidator,
		'default' : default_manufacturer
	    },
	    {
		'type': 'input',
		'name': 'modelNumber',
		'message': '[mandatory] What is Model number? (e.g. IM6001, SM-G973N)',
		'validate': DataValidator,
		'default' : default_model_number
	    },
	    {
		'type': 'input',
		'name': 'marketingName',
		'message': '[mandatory] What is Marketing name? (e.g. Motion sensor, SmartThings Wifi)',
		'validate': DataValidator,
		'default' : default_marketing_name
	    },
	    {
		'type': 'list',
		'name': 'manufacturerCode',
		'message': 'What is Manudacturer code?',
		'choices': ['000:Undefined', '101:Samsung mobile communication', '102:Samsung VD', '103:Samsung DA', '201:Smartthing', '501:Samjin'],
		'filter': lambda val: val[:3]
	    }
	]

	answers = prompt(questions, style=style)
	return answers

def help():
	print('set a device information \n')

	print('USAGE')
	print('  $ ./device_gen.py [DEVICE_TYPE] [FILE_PATH] \n')

	print('ARGUMENTS')
	print('  DEVICE_TYPE  Device type to distinguish whether it is a mass product or not')
	print('                - normal : this is a mass product, it will delete the unnecessary items (serialNumber, privateKey, publicKey) in device_info.json file automatically.')
	print('                - test : this is a test device, it will keep the items (serialNumber, privateKey, publicKey) in device_info.json file.')
	print('  FILE_PATH    the path of "device_info.json" file. \n')

	print('EXAMPLE')
	print('  %s:' % colored('For mass production', 'yellow'))
	print('    $ ./device_gen.py %s [st-device-sdk-c-ref path]/apps/[chip name]/[project name]/main/device_info.json' % (colored('normal', 'blue')))
	print('  %s:' % colored('For test', 'yellow'))
	print('    $ ./device_gen.py %s [st-device-sdk-c-ref path]/apps/[chip name]/[project name]/main/device_info.json' % (colored('test', 'blue')))
	exit()

def checkArgument():

	param_count = len(sys.argv)

	if param_count == 1:
		help()
		exit()
	elif param_count == 2:
		param = sys.argv[1]
		if param == "help" or param == "--help":
			help()
			exit()
	elif param_count == 3:
		return True
	else:
		print('\n%s Invalid option (Use ./device_info.py help)' % (colored('Error!!', 'red')))
		return False

def checkFileExistence(filePath):
	try:
		with open(filePath, 'r') as f:
			return True
	except IOError as e:
		return False
	except FileNotFoundError as e:
		return False

def getDeviceInformation(deviceInfoPath):
	global default_firmware_version, default_manufacturer, default_model_number, default_marketing_name, default_manufacturer_code

	# read device_info.json file.
	with open(deviceInfoPath, 'r') as file:
	    dicDeviceInfo = json.load(file)

	dicInDeviceInfo = dicDeviceInfo['deviceInfo']

	if 'firmwareVersion' in dicInDeviceInfo:
		default_firmware_version = dicInDeviceInfo['firmwareVersion']

	if 'manufacturerName' in dicInDeviceInfo:
		default_manufacturer = dicInDeviceInfo['manufacturerName']

	if 'modelNumber' in dicInDeviceInfo:
		default_model_number = dicInDeviceInfo['modelNumber']

	if 'marketingName' in dicInDeviceInfo:
		default_marketing_name = dicInDeviceInfo['marketingName']

	if 'manufacturerCode' in dicInDeviceInfo:
		default_manufacturer_code = dicInDeviceInfo['manufacturerCode']

	return True

def updateDeviceInformation(productInfo, deviceInfoPath):

	jsonProductInfo = json.dumps(productInfo, ensure_ascii=False, indent=4, separators=(',',': '))

	dictProductInfo = json.loads(jsonProductInfo)

	# read device_info.json file.
	with open(deviceInfoPath, 'r') as file:
		dicDeviceInfo = json.load(file)

	dicInDeviceInfo = dicDeviceInfo['deviceInfo']

	if stnv_flag == True:
		if 'serialNumber' in dicInDeviceInfo:
			dicInDeviceInfo.pop('serialNumber')
		if 'privateKey' in dicInDeviceInfo:
			dicInDeviceInfo.pop('privateKey')
		if 'publicKey' in dicInDeviceInfo:
			dicInDeviceInfo.pop('publicKey')

	# update product information in device_info.json file.
	dicInDeviceInfo.update(dictProductInfo)

	# write device_info.json file.
	with open(deviceInfoPath, 'w') as file:
	     file.write(json.dumps(dicDeviceInfo, ensure_ascii=False, indent=4, separators=(',',': ')))

	return True

def displayTitle():
	#os.system('clear')
	custom_fig = Figlet(font='slant')
	print(custom_fig.renderText('STDK CLI'))

	text = colored('Please add product information', 'green')
	print(text)

def main():
	global stnv_flag;

	result = checkArgument()
	if result == False:
		exit()

	device_type = sys.argv[1]

	if device_type == "normal":
		stnv_flag = True
	elif device_type == "test":
		stnv_flag = False
	else:
		print('%s Invalid option name (%s)' % (colored('Error!!', 'red'), device_type))
		exit()

	deviceInfoPath = sys.argv[2]

	result = checkFileExistence(deviceInfoPath)
	if result == False:
		text = colored('Error!!', 'red')
		print('\n%s we cannot find the device_info.json file in app directory (%s)' % (text, deviceInfoPath))
		exit()

	displayTitle()

	getDeviceInformation(deviceInfoPath)

	productInfo = askProductInformation()
	if not productInfo:
	    exit()

	result = updateDeviceInformation(productInfo, deviceInfoPath)

	if result == True:
		text = colored('Product Information is updated in device_info.json file', 'yellow')
		print('\n%s (Output : %s)' % (text, deviceInfoPath))
		os.system('cat %s' % (deviceInfoPath))
		print('\n')
	exit()

if __name__ == '__main__':
	main()

