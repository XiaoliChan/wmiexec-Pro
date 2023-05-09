import logging
import uuid
import sys

from io import StringIO
from impacket.dcerpc.v5.dtypes import NULL

class executeVBS_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    @staticmethod
    def checkError(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
        if call_status != 0:
            from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
        else:
            logging.info('%s - OK' % banner)

    def ExecuteVBS(self, vbs_file=None, vbs_content=None, filer_Query=None, timer=1000, returnTag=False, BlockVerbose=False, iWbemServices=None, return_iWbemServices=False):
        if vbs_content == None and vbs_file != None:
            with open(vbs_file,'r') as f: vbs_content = f.read()
        
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        tag = "windows-object-" + str(uuid.uuid4())

        # Copy from wmipersist.py
        # Install ActiveScriptEventConsumer
        activeScript, _ = iWbemServices.GetObject('ActiveScriptEventConsumer')
        activeScript = activeScript.SpawnInstance()
        activeScript.Name = tag
        activeScript.ScriptingEngine = 'VBScript'
        activeScript.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        activeScript.ScriptText = vbs_content
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        iWbemServices.PutInstance(activeScript.marshalMe()) if BlockVerbose==True else self.checkError('Adding ActiveScriptEventConsumer: %s' % tag, iWbemServices.PutInstance(activeScript.marshalMe()))
        #result=sys.stdout.getvalue()
        sys.stdout = current

        if filer_Query is not None:
            eventFilter, _ = iWbemServices.GetObject('__EventFilter')
            eventFilter = eventFilter.SpawnInstance()
            eventFilter.Name = tag
            eventFilter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            eventFilter.Query = filer_Query
            eventFilter.QueryLanguage = 'WQL'
            eventFilter.EventNamespace = r'root\cimv2'
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            iWbemServices.PutInstance(eventFilter.marshalMe()) if BlockVerbose==True else self.checkError('Adding EventFilter: %s' % tag, iWbemServices.PutInstance(eventFilter.marshalMe()))
            sys.stdout = current

        else:
            # Timer
            wmiTimer, _ = iWbemServices.GetObject('__IntervalTimerInstruction')
            wmiTimer = wmiTimer.SpawnInstance()
            wmiTimer.TimerId = tag
            wmiTimer.IntervalBetweenEvents = int(timer)
            #wmiTimer.SkipIfPassed = False
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            iWbemServices.PutInstance(wmiTimer.marshalMe()) if BlockVerbose==True else self.checkError('Adding IntervalTimerInstruction: %s' % tag, iWbemServices.PutInstance(wmiTimer.marshalMe()))
            sys.stdout = current

            # EventFilter
            eventFilter,_ = iWbemServices.GetObject('__EventFilter')
            eventFilter =  eventFilter.SpawnInstance()
            eventFilter.Name = tag
            eventFilter.CreatorSID =  [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            eventFilter.Query = 'select * from __TimerEvent where TimerID = "%s" ' % tag
            eventFilter.QueryLanguage = 'WQL'
            eventFilter.EventNamespace = r'root\subscription'
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            iWbemServices.PutInstance(eventFilter.marshalMe()) if BlockVerbose==True else self.checkError('Adding EventFilter: %s' % tag, iWbemServices.PutInstance(eventFilter.marshalMe()))
            sys.stdout = current

        # Binding EventFilter & EventConsumer
        filterBinding, _ = iWbemServices.GetObject('__FilterToConsumerBinding')
        filterBinding = filterBinding.SpawnInstance()
        filterBinding.Filter = '__EventFilter.Name="%s"' % tag
        filterBinding.Consumer = 'ActiveScriptEventConsumer.Name="%s"' % tag
        filterBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        iWbemServices.PutInstance(filterBinding.marshalMe()) if BlockVerbose==True else self.checkError('Adding FilterToConsumerBinding',iWbemServices.PutInstance(filterBinding.marshalMe()))
        sys.stdout = current
        
        if returnTag == True:
            if return_iWbemServices == True:
                return tag, iWbemServices
            else:
                return tag

    def remove_Event(self, tag, BlockVerbose=False, iWbemServices=None):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        
        if BlockVerbose == True:
            iWbemServices.DeleteInstance('ActiveScriptEventConsumer.Name="%s"' % tag)
            iWbemServices.DeleteInstance('__EventFilter.Name="%s"' % tag)
            iWbemServices.DeleteInstance('__IntervalTimerInstruction.TimerId="%s"' % tag)
            iWbemServices.DeleteInstance(r'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"%s\"",'r'Filter="__EventFilter.Name=\"%s\""' % (tag, tag))
        else:
            self.checkError('Removing ActiveScriptEventConsumer: %s' % tag, iWbemServices.DeleteInstance('ActiveScriptEventConsumer.Name="%s"' % tag))
            self.checkError('Removing EventFilter: %s' % tag, iWbemServices.DeleteInstance('__EventFilter.Name="%s"' % tag))
            self.checkError('Removing IntervalTimerInstruction: %s' % tag, iWbemServices.DeleteInstance('__IntervalTimerInstruction.TimerId="%s"' % tag))
            self.checkError('Removing FilterToConsumerBinding', iWbemServices.DeleteInstance(r'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"%s\"",'r'Filter="__EventFilter.Name=\"%s\""' % (tag, tag)))

    def deep_RemoveEvent(self, iWbemServices=None):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        for i in ['ActiveScriptEventConsumer', '__EventFilter', '__IntervalTimerInstruction', '__FilterToConsumerBinding']:
            while True:
                try:
                    iEnumWbemClassObject = iWbemServices.ExecQuery("select * from %s" %i)
                    class_ = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                    if i == "__IntervalTimerInstruction":
                        self.checkError('Removing %s: %s' % (i, class_.TimerId), iWbemServices.DeleteInstance('%s.Name="%s"' % (i, class_.TimerId)))
                    elif i == "__FilterToConsumerBinding":
                        self.checkError('Removing %s' %i, iWbemServices.DeleteInstance(r'__FilterToConsumerBinding.Consumer="%s",'r'Filter="%s"' %(class_.Consumer.replace('"','\\"'), class_.Filter.replace('"','\\"'))))
                    else:
                        self.checkError('Removing %s: %s' % (i, class_.Name), iWbemServices.DeleteInstance('%s.Name="%s"' % (i, class_.Name)))
                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        pass
                    else:
                        print('[+] %s has been cleaned!' %i)
                        break
