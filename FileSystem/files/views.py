from django.http.response import Http404
from django.shortcuts import render
import jwt
import json
import sys
import os
import datetime
import time
import requests
import base64
from django.conf import settings
import uuid
from django.http import JsonResponse, HttpResponse
from files.models import (UserTable, UserOtp, UserTokens)
import datetime as DT
from rest_framework import status
from rest_framework.response import Response
from datetime import datetime, time, timedelta, date
import time
import random
from django.utils import timezone
import pytz
import time
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_411_LENGTH_REQUIRED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR
)
import functools 
import operator
import re
import urllib
from rest_framework.views import APIView
import random
import mysql.connector
import os
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
import os.path
import shutil
import ntpath
from urllib.request import urlopen
from urllib.parse import urlparse
import wget

def validateRequiredFields(receivedJsonData):
    try:
        validation = []
        if "firstName" in receivedJsonData:
            firstName = receivedJsonData["firstName"]
            if not bool(firstName):
               validation.append("firstName can't be empty") 
        else:
            validation.append("firstName is required")
        if "lastName" in receivedJsonData:
            lastName = receivedJsonData["lastName"]
            if not bool(lastName):
                validation.append("lastName can't be empty") 
        else:
            validation.append("lastName is required")
        
        if "lastName" in receivedJsonData:
            lastName = receivedJsonData["lastName"]
            if not bool(lastName):
                validation.append("lastName can't be empty") 
        else:
            validation.append("lastName is required")
        if "contactNumber" in receivedJsonData:
            contactNumber = receivedJsonData["contactNumber"]
            if not bool(contactNumber):
                validation.append("contactNumber can't be empty") 
        else:
            validation.append("contactNumber is required")
        if "email" in receivedJsonData:
            email = receivedJsonData["email"]
            if not bool(email):
                validation.append("email can't be empty") 
            else:
                isEmailValid = re.search(r"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$", email)
                if not isEmailValid:
                    validation.append('Invalid email')
        else:
            validation.append("email is required")
        
        if "password" in receivedJsonData:
            password = receivedJsonData["password"]
            if not bool(password):
                validation.append("password can't be empty") 
        else:
            validation.append("password is required")
        if "userType" in receivedJsonData:
            userType = receivedJsonData["userType"]
            if not bool(userType):
                validation.append("userType can't be empty") 
            if userType not in [1 , 2]:
                validation.append("invalid user type") 
        else:
            validation.append("userType is required")
        message = validation                
    except Exception as e:
        tb = sys.exc_info()[2]
        errorMessage = ''
        if hasattr(e, 'message'):
            errorMessage = e.message
        else:
            errorMessage = e
        message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb)}
    finally:
        return message
    
def generateJwtToken():
    try:
        currentTime = datetime.today()
        seconds = int(currentTime.timestamp())
        expirationTime = seconds + 3600
        key = 'secret'
        encoded = jwt.encode({'exp': expirationTime}, key, algorithm='HS256')
        return encoded
    except Exception as e:
        errorMessage = ''
        if hasattr(e, 'message'):
            errorMessage = e.message
        else:
            errorMessage = e
        print(errorMessage)
        return JsonResponse({'error':str(errorMessage)})

class VerifyEmail(APIView):
    def post(self, request, *args, **kwargs):
        try:
            receivedJsonData = request.data
            status = HTTP_404_NOT_FOUND
            if receivedJsonData:
                email = receivedJsonData["email"]
                otp = receivedJsonData["otp"]
                result = UserTable.objects.filter(email=email, isActive=1).values()
                if len(result) > 0:
                    message = {"message" : "email already registered."}
                else:
                    records = UserOtp.objects.filter(otp=otp, email=email)
                    if len(records) != 0:
                        status = HTTP_200_OK
                        UserOtp.objects.filter(otp=otp, email=email).update(isActive=0)
                        UserTable.objects.filter(email=email).update(isActive=1)
                        
                        message = {"message" : "Email Verified."}
                    else:
                        message = {"message" : "Email or otp is wrong."}
            else:
                message = {"message" : "Empty Request"}

        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)

class SignUp(APIView):
    def post(self, request, *args, **kwargs):
        try:
            receivedJsonData = request.data
            status = HTTP_404_NOT_FOUND
            if receivedJsonData:
                validationResponse = validateRequiredFields(receivedJsonData)
                if len(validationResponse) == 0:
                    
                    firstName = receivedJsonData["firstName"]
                    lastName = receivedJsonData["lastName"]
                    contactNumber = receivedJsonData["contactNumber"]
                    email = receivedJsonData["email"]
                    password = receivedJsonData["password"]
                    isActive = 2
                    createdOn = datetime.now()
                    userType = receivedJsonData["userType"]
                    result = UserTable.objects.filter(email=email, isActive=1).values()
                    if len(result) > 0:
                        message = {"message" : "email already registered."}
                    else:
                        expiredOn = createdOn + timedelta(hours=1)
                        number = random.randint(1000,9999)
                        userOtpObj = UserOtp()
                        userObj = UserTable()
                        
                        password_bytes = bytes(str(password), "utf-8")
                        base64_bytes = base64.b64encode(password_bytes)
                        password = base64_bytes.decode('ascii')
                        
                        userObj.firstName = firstName
                        userObj.lastName = lastName
                        userObj.contactNumber = contactNumber
                        userObj.email = email
                        userObj.password = password
                        userObj.isActive = isActive
                        userObj.createdOn = createdOn
                        userObj.userType = userType
                        
                        userOtpObj.otp = number
                        userOtpObj.isActive = 1
                        userOtpObj.email = email
                        userOtpObj.createdOn = createdOn
                        sendEmail("Your OTP is : "+str(number), "OTP", email)
                        userObj.save()
                        userOtpObj.save()
                        status = HTTP_200_OK
                        
                        message = {"message" : "User registered successfully."}
                        
                else:
                    message = {"message" : str(validationResponse)}
            else:
                message = {"message" : "Empty Request"}

        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)

class Login(APIView):
    def post(self, request, *args, **kwargs):
        try:
            status = HTTP_404_NOT_FOUND
            receivedJsonData = request.data
            if receivedJsonData:
                if "email" in receivedJsonData and "password" in receivedJsonData:
                    email = receivedJsonData["email"]
                    password = receivedJsonData["password"]
                    
                    message_bytes = bytes(str(password), "utf-8")
                    base64_bytes = base64.b64encode(message_bytes)
                    password = base64_bytes.decode('ascii')
                    response = UserTable.objects.filter(email=email, password=password, isActive=1).values()
                    if len(response) > 0:
                        for items in response:
                            id = items["id"]
                            emailId = items["email"]
                        jwtToken = generateJwtToken()
                        
                        if not isinstance(jwtToken, str):
                            jwtToken = jwtToken.decode('utf-8')
                        
                        userTokensObj = UserTokens()
                        userTokensObj.userId = id
                        userTokensObj.accessToken = jwtToken
                        userTokensObj.isActive = 1
                        userTokensObj.save()
                        
                        message = {
                            "userId": id, 
                            "email":emailId,
                            "token": jwtToken,
                        }
                else:
                    message = {"message" : "email and password is required"}
            else:
                message = {"message" : "Empty Request"}
                
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)
        
class Logout(APIView):
    def get(self, request, format=None):
        try:            
            status = HTTP_404_NOT_FOUND
            data = ""
            headers = request.META
            jwtToken = headers["HTTP_AUTHORIZATION"]
            row = UserTokens.objects.filter(accessToken=jwtToken, isActive=1).values()
            if len(row) > 0:
                UserTokens.objects.filter(accessToken=jwtToken, isActive=1).update(isActive=0)
                status = HTTP_200_OK
                data = "User logged out successfully."
            else:
                data = "No active user found for this token."
            message = {"data": data }
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message":"Exception "+str(errorMessage) +" occurred at line number "+ str(tb.tb_lineno)
            }
        finally:
            return Response(message,status)        
            
class UploadFile(APIView):
    def post(self, request, *args, **kwargs):
        try:
            headers = request.META
            receivedJsonData = request.data
            status = HTTP_404_NOT_FOUND
            if "HTTP_AUTHORIZATION" in headers:
                jwtToken = headers["HTTP_AUTHORIZATION"]
                connectionResponse = getConn()
                mydb = connectionResponse["mydb"]
                cursor = connectionResponse["cursor"]
                singleSql = ("select userTable.id FROM `userTokens` "+
                "JOIN userTable ON userTokens.id = userTokens.id "+
                "where userTokens.accessToken=%s and userTokens.isActive=%s and userTable.isActive=%s")
                inputs = (jwtToken, 1, 1, )
                cursor.execute(singleSql, inputs)
                row = cursor.fetchall()[:1]
                if len(row) == 1:
                    if "fileName" in receivedJsonData:
                        fileName = (receivedJsonData["fileName"])
                        fileName = fileName.replace("\\","/")
                        logsDirectory = "controller"
                        if not os.path.exists(logsDirectory):
                            os.makedirs(logsDirectory)
                        else:
                            workingDir = os.getcwd()
                            targetDir = workingDir + "/" + logsDirectory
                            targetDir = targetDir.replace("/","\\")
                            targetDir = targetDir + "/"
                            extractedFileNameFromPath = ntpath.basename(fileName)
                            filesInDir = os.listdir(targetDir)
                            if extractedFileNameFromPath not in filesInDir:
                                shutil.copy(fileName, targetDir)
                                status = HTTP_200_OK
                                message = {'message':"File Uploaded"}
                                
                            else:
                                message = {'message':"File already exists"}
                    else:
                        message = {'message':"fileName required"}
                else:
                    message = {'message':"Authorzation failed, login again"}
            else:
                message = {'message':"Authorization Missing"}
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)
    
class ListDirectory(APIView):
    def get(self, request, *args, **kwargs):
        try:
            headers = request.META
            receivedJsonData = request.data
            status = HTTP_404_NOT_FOUND
            if "HTTP_AUTHORIZATION" in headers:
                jwtToken = headers["HTTP_AUTHORIZATION"]
                connectionResponse = getConn()
                mydb = connectionResponse["mydb"]
                cursor = connectionResponse["cursor"]
                singleSql = ("select userTable.id FROM `userTokens` "+
                "JOIN userTable ON userTokens.id = userTokens.id "+
                "where userTokens.accessToken=%s and userTokens.isActive=%s and userTable.isActive=%s")
                inputs = (jwtToken, 1, 1, )
                cursor.execute(singleSql, inputs)
                row = cursor.fetchall()[:1]
                if len(row) == 1:
                    logsDirectory = "controller"
                    
                    workingDir = os.getcwd()
                    targetDir = workingDir + "/" + logsDirectory
                    filesInDir = os.listdir(targetDir)
                    message = {'listOfFiles':filesInDir}
                    status = HTTP_200_OK
                    
                else:
                    message = {'message':"Authorzation failed, login again"}
            else:
                message = {'message':"Authorization Missing"}
                
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)
        

def getConn():
    counts = 0
    while True:
        try:
            db = settings.DATABASES['default']
            mydb = mysql.connector.connect(host=db['HOST'], user=db['USER'], passwd=db['PASSWORD'], database=db['NAME'], port=db['PORT'], use_pure=True)
            cursor = mydb.cursor(prepared=True)
            return {
                "mydb":mydb,
                "cursor": cursor
            }
        except mysql.connector.Error as err:
            tb = sys.exc_info()[2]
            errorMessage = ""
            if hasattr(err, 'message'):
                errorMessage = err.message
            else:
                errorMessage = err
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ""
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
    return {}

def sendEmail(data, subject, userEmail = ""):
    try:
        mailhost = os.getenv("EMAIL_HOST")
        mailPassword = os.getenv("EMAIL_PASSWORD")
        emailSender = os.getenv("EMAIL_SENDER")
        emailReceiver = os.getenv("EMAIL_RECEIVER")    
        
        if userEmail != "":
            emailReceiver = userEmail

        msg = MIMEMultipart()
        message = data

        # setup the parameters of the message
        host = mailhost
        password = mailPassword
        msg['from'] = emailSender
        msg['to'] = emailReceiver
        msg['subject'] = "Verify OTP -" +str(subject)
        # add in the message body
        msg.attach(MIMEText(message, 'plain'))
        #create server
        smtpserver = smtplib.SMTP("smtp.gmail.com",587)
        smtpserver.ehlo()
        smtpserver.starttls()
        smtpserver.ehlo()
        smtpserver.login(emailSender, mailPassword)   
        smtpserver.sendmail(msg['From'], emailReceiver, str(msg))
        # send the message via the server.
        smtpserver.quit()    
        print("Successfully sent email to %s:" % (msg['To']))

    except Exception as e:
        tb = sys.exc_info()[2]
        errorMessage = ''
        if hasattr(e, 'message'):
            errorMessage = e.message
        else:
            errorMessage = e

        print("Email Sending Exception "+str(errorMessage) +" occurred at line number "+ str(tb.tb_lineno))
        return {"status":False, "error": "Email Sending Exception "+str(errorMessage) +" occurred at line number "+ str(tb.tb_lineno)}

def CreateFolder():
    try:
        logsDirectory = "controller"
        if not os.path.exists(logsDirectory):
            os.makedirs(logsDirectory)
        
    except:
        e = sys.exc_info()[0]
        print("Error in adding Logs: {}".format(e))
        
class DownloadFile(APIView):
    def post(self, request, *args, **kwargs):
        try: 
            headers = request.META
            receivedJsonData = request.data
            status = HTTP_404_NOT_FOUND
            if "HTTP_AUTHORIZATION" in headers:
                jwtToken = headers["HTTP_AUTHORIZATION"]
                connectionResponse = getConn()
                mydb = connectionResponse["mydb"]
                cursor = connectionResponse["cursor"]
                singleSql = ("select userTable.userType, userTokens.accessToken FROM `userTable`, `userTokens` "+
                "where userTokens.accessToken=%s and userTokens.isActive=%s and userTable.isActive=%s")
                inputs = (jwtToken, 1, 1, )
                cursor.execute(singleSql, inputs)
                row = cursor.fetchall()[:1]
                if len(row) == 1:
                    for rowObject in row:
                        userType = rowObject[0]
                        if  userType == 1: 
                            fileName = receivedJsonData["fileName"]
                            extractedFileNameFromPath = ntpath.basename(fileName)
                            targetPath = os.getenv("TARGET_PATH")
                            if extractedFileNameFromPath not in targetPath:
                                wget.download(fileName, targetPath)
                                message = {'message':"File Downloaded"}
                            else:
                                message = {'message':"File alredy exists"}
                        else:
                            message = {'message':"You don't have access to download files"}
                else:
                    message = {'message':"Authorzation failed, login again"}
            else:
                message = {'message':"Authorization Missing"}
        except Exception as e:
            tb = sys.exc_info()[2]
            errorMessage = ''
            if hasattr(e, 'message'):
                errorMessage = e.message
            else:
                errorMessage = e
            message = {"message" : "Exception " + str(errorMessage) + "at line number "+str(tb.tb_lineno)}
        finally:
            return Response(message, status)