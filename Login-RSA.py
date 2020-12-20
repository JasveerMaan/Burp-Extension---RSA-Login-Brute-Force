from burp import IBurpExtender, IHttpListener, IMessageEditorTab, IMessageEditorTabFactory, IParameter
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import requests
import json


http_proxy = "http://127.0.0.1:8080"
https_proxy = "http://127.0.0.1:8080"
ftp_proxy = "http://127.0.0.01:8080"

proxyDict = {"http":http_proxy,"https":https_proxy,"ftp":ftp_proxy}

import requests #You will need to ensure that Jython has access to python [requests] & Selenium module

import json

requests.packages.urllib3.disable_warnings()

#Login Steps
getRandom = "https://127.0.0.1/api/home-getRandom"
doLogin = "https://127.0.0.1/home-login"

#Selenium Variables
#Target Application URL (which loads the JavaScript Libraries)
target = "https://127.0.0.1/home"

#Put the drivers in the same folder as your extension
exactPathToDriver = r'C:\Users\XXXX\XXXX\geckodriver.exe'

#set selenium options, set headless of True if you prefer
options = Options()
options.headless = False

driver = webdriver.Firefox(options=options, executable_path=exactPathToDriver)
driver.get(target)


class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory, IParameter):

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.registerHttpListener(self)
		callbacks.setExtensionName("Burp Ext2 Template :]")
	
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

		if toolFlag != self.callbacks.TOOL_REPEATER and toolFlag != self.callbacks.TOOL_SCANNER and toolFlag != self.callbacks.TOOL_INTRUDER and toolFlag != self.callbacks.TOOL_EXTENDER:
			return
		
		if messageIsRequest: # This will be true of the message which enters this function is a "Request"
			request = messageInfo.getRequest()
			requestHTTPService = messageInfo.getHttpService();
			requestInfo = self.helpers.analyzeRequest(requestHTTPService,request)

			captured_headers = requestInfo.getHeaders()
			body_offset = requestInfo.getBodyOffset()
			body_bytes = request[body_offset:]		
			body = self.helpers.bytesToString(body_bytes)
			json_data = body
			
			#Checking for the domain
			for headers in captured_headers:
				if "127.0.0.1" in headers:
					flag = True

			if flag:
				print "[*] Starting script"
				print "[*] Retrieving c_string value"
				#Get the c_string (plaintext) password - For repeater to submit plaintext
				parameters = requestInfo.getParameters()
				#for loop to find c_string parameter
				for x in parameters:
					#print(x) -> this will print like "burp@frb110...."
					print(x.getName() + " = " + x.getValue())
					if "c_string" in x.getName():
						break

				#Get random number and RSA key from the server:
				print "[*] Response from /api/ext2-getRandom:"
				driver.get(getRandom)
				element = driver.find_element_by_tag_name("body")
				response = element.get_attribute("innerHTML")
				#This will print entire response without HTML tags
				print response

				#Printing just RandomNumber
				print "[*] RandomNumber:"
				#print RandomKey
				RandomKey = json.loads(response)
				RandomKeyValue = (RandomKey["RandomNumber"])
				print RandomKeyValue

				#Printing RSA Public Key
				print "[*] RSA Public Key:"
				RSAPublicKey = json.loads(response)
				ModulusValue = (RSAPublicKey["Modulus"])
				print ModulusValue

				#This prints c_string value!
				password = x.getValue()
				#print password
				driver.get(target)
				createPINBlock = "window.createPINBlock"+"("+"\""+password+ "\""+","+"\""+RandomKeyValue+"\""+")"
				#print createPINBlock
				driver.execute_script("window.modulusString = '"+ModulusValue+"'")

				driver.execute_script(createPINBlock)
				c_string = driver.execute_script("return window.getEncryptedUserLoginMsg()")
				print "[*] Printing Encrypted Value"
				print c_string

				p_string = driver.execute_script("return window.getEncodingParameter()")
				print "[*] Printing p_string"
				print p_string
				
				new_body = "username=username&c_string="+c_string+"&p_string="+p_string+"&randomNumber="+RandomKeyValue
				print "[*] Created new body:"
				print new_body

			updatedRequest = self.helpers.buildHttpMessage(captured_headers, new_body)
			messageInfo.setRequest(updatedRequest)



		
