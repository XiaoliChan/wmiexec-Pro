import logging
import uuid
import sys

from io import StringIO
from impacket.dcerpc.v5.dtypes import NULL

from lib.checkError import checkError


class executeVBS_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def ExecuteVBS(self, vbs_file=None, vbs_content=None, filer_Query=None, timer=1000, returnTag=False, BlockVerbose=False, iWbemServices=None, return_iWbemServices=False):
        if not vbs_content and vbs_file:
            with open(vbs_file, "r") as f:
                vbs_content = f.read()
        
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        tag = f"windows-object-{str(uuid.uuid4())}"

        # Copy from wmipersist.py
        # Install ActiveScriptEventConsumer
        activeScript, _ = iWbemServices.GetObject("ActiveScriptEventConsumer")
        activeScript = activeScript.SpawnInstance()
        activeScript.Name = tag
        activeScript.ScriptingEngine = "VBScript"
        activeScript.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        activeScript.ScriptText = vbs_content
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        marshalled = activeScript.marshalMe()
        sys.stdout = current
        iWbemServices.PutInstance(marshalled) if BlockVerbose else checkError(f"Adding ActiveScriptEventConsumer: {tag}", iWbemServices.PutInstance(marshalled))

        if filer_Query:
            eventFilter, _ = iWbemServices.GetObject("__EventFilter")
            eventFilter = eventFilter.SpawnInstance()
            eventFilter.Name = tag
            eventFilter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            eventFilter.Query = filer_Query
            eventFilter.QueryLanguage = "WQL"
            eventFilter.EventNamespace = "root\\cimv2"
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            marshalled = eventFilter.marshalMe()
            sys.stdout = current
            iWbemServices.PutInstance(marshalled) if BlockVerbose else checkError(f"Adding EventFilter: {tag}", iWbemServices.PutInstance(marshalled))

        else:
            # Timer
            wmiTimer, _ = iWbemServices.GetObject("__IntervalTimerInstruction")
            wmiTimer = wmiTimer.SpawnInstance()
            wmiTimer.TimerId = tag
            wmiTimer.IntervalBetweenEvents = int(timer)
            #wmiTimer.SkipIfPassed = False
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            marshalled = wmiTimer.marshalMe()
            sys.stdout = current
            iWbemServices.PutInstance(marshalled) if BlockVerbose else checkError(f"Adding IntervalTimerInstruction: {tag}", iWbemServices.PutInstance(marshalled))

            # EventFilter
            eventFilter,_ = iWbemServices.GetObject("__EventFilter")
            eventFilter =  eventFilter.SpawnInstance()
            eventFilter.Name = tag
            eventFilter.CreatorSID =  [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            eventFilter.Query = f'select * from __TimerEvent where TimerID = "{tag}"'
            eventFilter.QueryLanguage = "WQL"
            eventFilter.EventNamespace = "root\\subscription"
            # Don't output verbose
            current=sys.stdout
            sys.stdout = StringIO()
            marshalled = eventFilter.marshalMe()
            sys.stdout = current
            iWbemServices.PutInstance(marshalled) if BlockVerbose else checkError(f"Adding EventFilter: {tag}", iWbemServices.PutInstance(marshalled))

        # Binding EventFilter & EventConsumer
        filterBinding, _ = iWbemServices.GetObject('__FilterToConsumerBinding')
        filterBinding = filterBinding.SpawnInstance()
        filterBinding.Filter = f'__EventFilter.Name="{tag}"'
        filterBinding.Consumer = f'ActiveScriptEventConsumer.Name="{tag}"'
        filterBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        marshalled = filterBinding.marshalMe()
        sys.stdout = current
        iWbemServices.PutInstance(marshalled) if BlockVerbose else checkError("Adding FilterToConsumerBinding", iWbemServices.PutInstance(marshalled))
        
        if returnTag:
            if return_iWbemServices:
                return tag, iWbemServices
            else:
                return tag

    def remove_Event(self, tag, BlockVerbose=False, iWbemServices=None):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        
        if BlockVerbose:
            iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{tag}"')
            iWbemServices.DeleteInstance(f'__EventFilter.Name="{tag}"')
            iWbemServices.DeleteInstance(f'__IntervalTimerInstruction.TimerId="{tag}"')
            iWbemServices.DeleteInstance(rf'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{tag}\"",Filter="__EventFilter.Name=\"{tag}\""')
        else:
            checkError('Removing ActiveScriptEventConsumer: %s' % tag, iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{tag}"'))
            checkError('Removing EventFilter: %s' % tag, iWbemServices.DeleteInstance(f'__EventFilter.Name="{tag}"'))
            checkError('Removing IntervalTimerInstruction: %s' % tag, iWbemServices.DeleteInstance(f'__IntervalTimerInstruction.TimerId="{tag}"'))
            checkError('Removing FilterToConsumerBinding', iWbemServices.DeleteInstance(rf'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{tag}\"",Filter="__EventFilter.Name=\"{tag}\""'))

    def deep_RemoveEvent(self, iWbemServices=None):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        for i in ["ActiveScriptEventConsumer", "__EventFilter", "__IntervalTimerInstruction", "__FilterToConsumerBinding"]:
            while True:
                try:
                    iEnumWbemClassObject = iWbemServices.ExecQuery(f"select * from {i}")
                    class_ = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                    if i == "__IntervalTimerInstruction":
                        checkError(f"Removing {i}: {class_.TimerId}", iWbemServices.DeleteInstance(f'{i}.Name="{class_.TimerId}"'))
                    elif i == "__FilterToConsumerBinding":
                        checkError(f"Removing {i}", iWbemServices.DeleteInstance(rf'__FilterToConsumerBinding.Consumer="{class_.Consumer.replace('"','\\"')}",Filter="{class_.Filter.replace('"','\\"')}"'))
                    else:
                        checkError(f"Removing {i}: {class_.Name}", iWbemServices.DeleteInstance(f'{i}.Name="{class_.Name}"'))
                except Exception as e:
                    if str(e).find("S_FALSE") < 0:
                        pass
                    else:
                        self.logger.info(f"{i} has been cleaned!")
                        break
