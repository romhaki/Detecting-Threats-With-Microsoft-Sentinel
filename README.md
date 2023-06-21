# Detecting Threats With Microsoft Sentinel


## Introduction
In this lab we will:
- Configure and Deploy Azure Resources such as Log Analytics Workspace, Virtual Machines, and Azure Sentinel
- Implement Network and Virtual Machine Security Best Practices
- Utilize Data Connectors to bring data into Sentinel for Analysis
- Understand Windows Security Event logs
- Configure Windows Security Policies
- Utilize KQL to query Logs
- Write Custom Analytic Rules to detect Microsoft Security Events
- Utilize MITRE ATT&CK to map adversary tactics, techniques, detection and mitigation procedures

#
<details>
<summary>
  
### Step 1: Deploying a VM and enabling JIT access

</summary>  
<br/>
 In this lab, we will first create the virtual machine (VM) inside a resource group. A resource group is simply a way to logical separate our cloud resources in Azure.
 One way to create a resource group is to search for 'Resource Group' in the portal searchbar, and then clicking 'Create'. We can then fill in the name and select the region desired for our resource group.
 Now, from the main page of the Azure portal, click 'Create a Resouce', then click create under 'Virtual Machine'.
   
  We will configure the virtual machine as follows:

  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/3618f855-5d9b-4c7e-b720-d7ec354cd9a1)

  Note that we have enabled 3389 as an inbound port. This will allow us to use Remote Desktop Protocol to access our VM. However, since we have enabled RDP on our VM, it may be subject to brute force attacks. To mitigate this threat, we will enable just-in-time (JIT) VM access. With JIT, we can limit access to our VM by time or even allow only our IP. More about JIT can be read <a href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage?tabs=jit-config-asc%2Cjit-request-asc">here</a>. To enable this, access Microsoft Defender for Cloud, which can be done by searching for this service via the search bar at the top of the portal. In the Environment Settings section of Microsoft Defender for Cloud, select ‘enable all plans’. This will give us access to the enhanced security features in our subscription which we will need to enable JIT. 

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/020cc87c-2f73-46e7-a7bf-16fd993b6518)

  Now, go to the Workload Protections in Microsoft Defender for Cloud via the left panel. Under ‘Advanced Protection’, select Just-in-time VM access. 
Now, enable JIT on the VM being used for the project:


![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/fc98a287-e2b0-4c16-a8ff-d2554c5666bd)


  From here, we can navigate to the settings page for our VM, and in the 'Connect' pane select ‘My IP’ as the Source IP and Request access.
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/bf9b82a5-1a69-49ef-a97a-1ecb0ad82bae)

  Now, the VM will only be allowed RDP access from the IP we are using. 

  </details>
  
  
  #
<details>
<summary>
  
### Step 2: Create a Log Analytics Workspace and Deploy Microsoft Sentinel 
</summary>  
<br/>
Now, we will create a Log Analytics Workspace and deploy Microsoft Sentinel. The Log Analytics workspace will collect and store the log data.

Search for Microsoft Sentinel in the Azure portal  search bar and click 'Create' to create a Log Analytics workspace. 

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/3009aacc-eecc-4b3c-9ed8-bbf60dc03dae)

As always, ensure the workspace is being applied to the correct Resource group. 

  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/d8d91acb-d520-4822-91be-14b7aef7db4b)


  Now, go to Microsoft Sentinel via the search bar, and add Sentinel to the workspace. 
  
  Initially, there will be nothing to display until we click the button which will prompt us to add Sentinel to the workspace:


![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/dcc965f0-f148-4784-9750-4b9958315fa6)

  Select the workspace we created and click 'Add'. 

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/91625f19-3e98-4050-b9f2-0d8b869ab0df)

  Now, we are able to access the logs workspace after navigating to Microsoft Sentinel. 
  </details>
  

  #
<details>
<summary>
  
### Step 3: Getting Data into Microsoft Sentinel  
</summary>  
<br/>
Now, we need to utilize a data connector to create a data collection rule to import data from the Windows VM so we can view detected incidents[b]. Under the ‘Data connectors’ tab under ‘Configuration’ in Sentinel, search for ‘Windows Security Events’ and select ‘Windows Security Events via AMA’ and click on  ‘Open Connector Page’.   

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/68692c10-5a6c-44ed-92f6-ebd549250462)

  
  From here, we can now click 'Create data collection rule'.

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/560956f9-16af-41cd-9d0d-9b3898577fff)

  Select the Windows VM resource that has been created, and create the rule. For this project we will stream ‘All Security Events’ as shown:
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/0a44a49a-d36c-4bc1-86de-c93b4c5ad9b7)
  
  Finally, click 'Create'. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/abb192d1-ef82-4a0e-b8b6-140e2eb857f3)
  
  Now, if we go back to the 'Data connectors' panel in Sentinel we can see that ‘Windows Security Events via AMA’ is now connected. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/4267e1a6-9e97-45bd-bb10-ddcaa2c7fc8b)

</details>



  #
<details>
<summary>
  
### Step 4: Generating Security Events  
</summary>  
<br/>
Since our VM is now connected to Sentinel and the Log Analytics workspace, we can now take actions within our Windows 10 VM that will create security alerts.
 Navigate to the VM in the Azure portal and ensure that the VM is running.
  
  We will now RDP into our VM. From a local Windows machine, the 'Remote Desktop Connection' program may be used to achieve this. Enter the public IP of the VM which can be found in the 'Networking' section of the VM's page. 
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/65252035-9a22-4689-ac52-418de8c0ea00)

  Inside the VM, access the 'Event Viewer' application which can be done by searching for it from the start menu. Navigate to Security which is under 'Windows Logs'. One event we can view is Event 4624 which corresponds to a successful login. We can use the find tool to highlight instances of this. Clicking the event will bring up more detailed information about the action. 
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/1a39583e-870e-48a8-8ca5-3a2ddcf262af)

 </details>
  
  
  #
<details>
<summary>
  
### Step 5: Using KQL to extract data  
</summary>  
<br/>
We can now use the Microsoft Sentinel SIEM to view security logs pertaining to our VM. In the ‘Logs’ section of the Log Analytics workspace created in Microsoft Sentinel, we can use Kusto Query Language, KQL, to extract the desired data.
  For instance, we can use the following query to show instances of successful logins:
  
  ```
  SecurityEvent
| where EventID == 4624
| project TimeGenerated, Computer, AccountName
 ```
   
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/0a494813-fc82-4197-a7bd-c9e70935e1f8)

  This shows the event from the Security Event table, showing the event with ID 4624, and shows the time the event was generated, the computer name.
Another event we can view is an unsuccessful login, which would have an EventID of 4625. To generate such an alert, we may attempt to RDP into the machine but provide an incorrect password on purpose. 
 </details>
 
   #
<details>
<summary>
  
### Step 6: Creating Analytic Rule with KQL & Generating Scheduled Tasks   
</summary>  
<br/>
Now, we can create analytic rules to be alerted about certain events. Upon the detection of a specified activity in our VM, an alert will be generated. In the analytics section of Microsoft Sentinel, there are various rule templates that may be used to automatically generate alerts. These are alerts built into the SIEM that we can start using to monitor our infrastructure. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/fb4666de-cd6e-46b3-a188-2354e3730931)

  <strong> Scheduled Task and Persistence Techniques: </strong>
 
  In this lab, we will used the scheduled task/job technique to simulate tactics done by adversaries. While some scheduled tasks can be harmless, such as starting a non-malicious program, threat actors often use this functionality to establish persistence. The MITRE attack framework discusses this technique in detail <a href="https://attack.mitre.org/techniques/T1053/">here</a>.
  
As stated, “Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time… Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence.” While the scheduled task we will create is harmless, such actions may be associated with malicious intent by threat actors." 
 
  In this lab, our scheduled task will not be malicious as we will be creating a scheduled task that opens a browser at a specific time. However, we will create an analytic rule that will monitor for this type of event so that we will be alerted in the SIEM about this kind of action.

  Since it is not enabled by default, we need to enable logging for a scheduled task creation. In our VM, we can open the ‘Local Security Policy’ application. Under ‘Advanced Audit Policy Configuration’ and ‘System Audit Policies’, we can select 'Object Access’. From here, select ‘Audit Other Object Access Events’ and enable both ‘success’ and ‘failure’ as shown. After completing this step, logging will be enabled for scheduled task events. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/10e1436e-74ef-41f3-9a2f-51c780b31635)


  <strong> Creating the Scheduled Task: </strong>
  
  Finally, scheduling a task in Windows 10 can be done by opening the ‘Task Scheduler’ application and using the ‘Create Task’ feature. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/169bf494-1c66-4874-8fbb-4c5cf3fc59fb)

  Under Triggers, set a time in the future. Under actions, we can set an action to start a program. In this example, I have chosen to start Microsoft Edge.
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/0efd3b55-5204-4d94-b7ae-89ed23878e71)

  The scheduled task creation will now also show up in the Security section of 'Event Viewer' in the VM with an Event ID of 4698. Now, we can create the analytic rule to alert us about this in our SIEM.
  
  <strong> Writing the analytic rule using KQL: </strong>
  In this step, we will use a KQL query to alert us when a scheduled task is created.
Note that when we run the query in the Logs section of the workspace, specific events can be expanded to show the ‘EventData’.  
  

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/d4078f44-31e1-490b-82d2-12b7dce3f90e)


In the ‘EventData’ section, we can find more useful information, such as the scheduled tasks name, the ClientProcessID, the username of the account that the task was created on, and more. We can use the 'parse' command in our KQL query to extract data from the 'EventData' Field that we find important, and use the 'project' command to display the data fields as columns:
  ```
  SecurityEvent                            
 | where EventID == 4698
 | parse EventData with * '<Data Name="SubjectUserName">' User '</Data>' *
 | parse EventData with * '<Data Name="TaskName">' NameofScheuduledTask '</Data>' *
 | parse EventData with * '<Data Name="ClientProcessId">' ClientProcessID '</Data>' *
 | project Computer, TimeGenerated, ClientProcessID, NameofScheuduledTask, User
  ```
  Under Results, this will now show us the Computer, Time Generated, the ClientProcessID, the name of the task that was scheduled, and the User. Thus, we can generate Event Data and place it into its own category for readability. This may be beneficial for the analyst investigating the logs. 
  
  We will now use this KQL logic to alert us when new scheduled tasks are created. Navigate back to Microsoft Sentinel, open the analytics workspace previously created. Open  ‘Analytics’ and click ‘Create’ to find the option to create a ‘Scheduled query rule’.
  We will create a new scheduled rule as follows:

  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/38907617-9739-4e0f-b127-a8fa44b7aa54)

  For the rule logic, use the KQL query that was created to extract our desired information: 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/65063ba6-76ee-4120-b81f-f8d50fc0d2c1)
  
  We will also utilize Alert Enrichment. The purpose of this is to provide more relevant context to our alerts.

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/ab749a0d-d0d5-4524-81dc-5ffaff499967)

  Under query scheduling, set the query to run every 5 minutes. It is 5 hours by default:
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/14b3135b-ec0c-4906-9a51-91a9345c0952)

  The full configuration for the scheduled rule is as follows: 

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/3edb77ee-8635-40a8-8822-a15132f4c398)

  
  After creating this rule, we can create another task in the Windows VM as before, and the alert will be triggered in Microsoft Sentinel. Once more tasks are created, we can view the occurrences in the ‘Incidents’ page of Microsoft Sentinel.

![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/81972c15-400f-49b2-8d22-6cb8c40a5f53)

  Since we utilized entity mapping when creating the scheduled rule, we can also see the information such as the user, machine name, task name, and the process ID which would help in an investigative process. The security analyst could now use this information along with other tools to evaluate the alert. 
  
 </details>
  
   #
<details>
<summary>
  
### Step 7: Using the MITRE ATT&CK Framework   
</summary>  
<br/>
The observed MITRE ATT&CK tactic that we have detected using the Microsoft Sentinel SIEM in this lab is <a href="https://attack.mitre.org/tactics/TA0003/">TA0003 Persistence</a>. This tactic is used by threat actors to maintain access to systems despite system restarts, changed credentials, or other events that could remove their access from systems. We can use the MITRE ATT&CK Framework to narrow down the specific technique a potential threat actor may be using in this lab, and we can identify the technique and sub-technique as <a href="https://attack.mitre.org/techniques/T1053/005/">T1053.005</a>.
  

  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/a58fbebc-452b-4f0b-b8e3-6241a3654254)

  
  <strong> Detection </strong>
  By logging specific Windows Event IDs with the help of Microsoft Sentinel, we were able to detect this activity. The MITRE ATT&CK Framework also outlines recommendations for detection. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/1941d435-a09f-42fb-a595-e475f63cc8de)


  
  <strong> Mitigation </strong> 
  One mitigation technique outlined in the MITRE ATT&CK Framework is <a href="https://attack.mitre.org/mitigations/M1018/">User Account Management, ID: M1018</a>.
  As shown, this technique can be mitigated by only authorizing administrators to create tasks on remote systems.
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/34df28cc-0648-4384-9286-4ab648352d0c)

  

  
 </details>
  
  
  

  
  
