# MessingUpWithBlueTeam
0. Intro:

https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/

1. History:

	virus:
	
	antivirus:
	
	+signature
	
		-Obfuscation, 
		
		 https://fr.wikipedia.org/wiki/Offuscation
		 
		-Polymorphism,	
		
		 https://fr.wikipedia.org/wiki/Virus_polymorphe
		 
		-Packing
		
	    	 https://fr.wikipedia.org/wiki/UPX
		 
		 
	+behavior
	
	preludes: 
	
		  sandboxing
		  
		  https://fr.wikipedia.org/wiki/Sandbox_(s%C3%A9curit%C3%A9_informatique)
		  
		  detects process creation..
		  
		  Access to some file..
		  
		  hook a few calls..
		  

2. windows malware detection

		  Signature
		  
			https://github.com/matterpreter/DefenderCheck
			
			Check if file is detected by defender, says which part exactly
			
		  AMSI  
		  
			Test your VM with Powersploit:
			
			https://github.com/PowerShellMafia/PowerSploit
			
			It'll get caught by AMSI:
			
			https://blog.f-secure.com/hunting-for-amsi-bypasses/
			
		  Sandbox
		  
			https://www.kaspersky.com/enterprise-security/wiki-section/products/sandbox
			
		  	https://www.virustotal.com/gui/home/upload
			
			https://cuckoosandbox.org/
			
		  ETW
		  
			https://docs.microsoft.com/fr-fr/windows/win32/wes/windows-event-log
			
		  SYSMON
		  
			https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
			
		  EDR
		  
			https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-endpoint-detection-and-response/
			
			https://www.mcafee.com/enterprise/fr-fr/security-awareness/endpoint/what-is-endpoint-detection-and-response.html
			
		  NTDLL HOOKING by EDR
			
		  Forensic if you get caugh
		  
		  
3. shhhhhhh:

		  Signature? ez, go fileless lol,
		  
		  AMSI is really easy to bypass/kill with Powershell
		  
				Obfuscation goes brrr
				
				https://github.com/tokyoneon/Chimera
				
				ISESteroids
				
				http://amsi.fail/
				
				https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
				
		  ETW as well
		  
				https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101
				
		  Sandbox Evasion
		  
				https://www.ptsecurity.com/ww-en/analytics/antisandbox-techniques/

		  Sysmon Evasion:
		  
				https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
				
				https://github.com/mkorman90/sysmon-config-bypass-finder
				
		  Living Of The Land
		  
				https://lolbas-project.github.io/#
				
		  EDR: many noise for not so much:
		  
		  	EDR UNHOOKING 101
			
				https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis
				
		  	Dynamic resolve
			
				https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/
				
			SysWhisper
			
				https://github.com/jthuraisamy/SysWhispers2

		  modify host to blackhole EDR console fqdn (lol)
		  
		  Block EDR console ip with netsh (lol)

		  Make Forensic harder:
		  
		  	Process injection
			
				https://attack.mitre.org/techniques/T1055/
				
			Reflective injection?
			
				https://powersploit.readthedocs.io/en/latest/CodeExecution/Invoke-ReflectivePEInjection/
				
			Process hollowing?
			
				https://github.com/snovvcrash/NimHollow	
				
		  	DLLinjection
			
				https://www.malekal.com/injection-de-code-pedll-injection-et-dropper/
				
		  C2 canals: blind IDS and IPS
		  
		  	HTTPS
				crypted
			DNS
				Sliver has a DNS C2 capacity! Cobalt Strike too!
				
				https://github.com/BishopFox/sliver
				
			Steganography: image inside a mail
			
				https://mobile.twitter.com/r0bf4lc/status/1285955250705387522
				
				https://h0mbre.github.io/Image_Based_C2_PoC/
				
				
		  Pivoting
		  
			HTTPS, meh:
			
				Suspicious for internal to internal workflow
				
			RDP
			
				EDR has often no idea, it depends on ETW, Sysmon and eventually AD Auditing
				
			SMB Named Pipes
			
				Hard to analyse correctly for analysts
				
        			Cobalt Strike has SMB Named Pipes Pivot
        			
				Meterpreter Too!
       				
				https://medium.com/@petergombos/smb-named-pipe-pivoting-in-meterpreter-462580fd41c5
				
			RPC
			
				Hard to analyse correctly for analysts
			
				Sliver has an awesome RPC Pivot :3


			https://www.malekal.com/rootkits-sur-windows/
			
		  Userland Rootkit
		  
			https://andreafortuna.org/2018/10/15/some-thoughts-about-windows-userland-rootkits/
			
		  Kernel Rookit
		  
			https://github.com/D4stiny/spectre
		  
		  Bring Your Own Interpreter
		  
			Silent Trinity:
			
				https://github.com/byt3bl33d3r/SILENTTRINITY
				
			IronPython
			
				https://www.bc-security.org/post/rebuilding-ironnetinjector-turlas-ironpython-toolkit/
				
				
Free AV to try

	Avira

	Avast
	
	Virustotal
	
		https://www.virustotal.com/gui/home/upload
  
  
Free EDR To try

	Wazuh		      
		https://wazuh.com/	
		
		
  
Free IPS To try

	Snort
	
	Suricata
		
		
		
		
		
		
		
		
		

