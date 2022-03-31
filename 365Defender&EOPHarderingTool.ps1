<#
.HAKKIMDA
	Mehmet PATLAKYİĞİT | Office Apps & Services MVP
	https://www.parlakyigit.net/
	Twitter:@mparlakyigit 
#>


<#
.NOTE
Bu PowerShell betiği ORCA raporu çıktısına göre Exchange Online Protection ve Microsoft Defender for Office 365 ürünlerinin sıkılaştırılmasını otomatize etmektedir.
#>

<#
.NOTE
Düzenleme yapılmayan rapor sonuçları
- DKIM 
- ip adres WhiteList ve e-mail ve domain WhiteListe
#>

#Microsoft 365 Connect
$username = Read-Host -Prompt "Admin User Name"
Read-Host -Prompt "Admin Password" -AsSecureString | ConvertFrom-SecureString | Out-File ".\credential.txt"
$Password = Get-Content ".\credential.txt" | ConvertTo-SecureString
$cred = New-Object System.Management.Automation.PSCredential ($username,$Password)

Set-ExecutionPolicy Unrestricted
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Credential $cred
Install-Module ORCA
Get-ORCAReport

$Domain_one = "mparlakyigit.onmicrosoft.com"
$Domain_two = "ozcanmandiraci.com"
$Domain_three = "parlakyigit.net"
$email = "security@parlakyigit.net"

#Yeni Paylaşılan Posta Kutusu oluşturulur.
New-Mailbox -Shared -Name "Security Team" -DisplayName "Security Team" -Alias security

#External PostMaster E-Mail Adress
Set-TransportConfig -ExternalPostmasterAddress $email

#Quarantine Policy
#Limitli Erişim-Alıcılar karantinaya alınan öğeleri görüntüleyebilir.Serbest bırakamaz.
#https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/quarantine-policies?view=o365-worldwide#create-quarantine-policies-in-powershell
New-QuarantinePolicy -Name NotificationEnabledPolicy -EndUserQuarantinePermissionsValue 27 -EsnEnabled $true

#Anti-spam inbound policy (Default)
#https://security.microsoft.com/antispam
set-HostedContentFilterPolicy -Identity Default -MarkAsSpamBulkMail on -BulkThreshold 6
Set-HostedContentFilterPolicy -Identity Default -EnableEndUserSpamNotifications $True
Set-HostedContentFilterPolicy -Identity Default -EndUserSpamNotificationFrequency 3
Set-HostedContentFilterPolicy -Identity Default -SpamAction Quarantine -SpamQuarantineTag NotificationEnabledPolicy
Set-HostedContentFilterPolicy -Identity Default -HighConfidenceSpamAction Quarantine 
Set-HostedContentFilterPolicy -Identity Default -HighConfidenceSpamQuarantineTag NotificationEnabledPolicy
Set-HostedContentFilterPolicy -Identity Default -PhishSpamAction Quarantine -PhishQuarantineTag NotificationEnabledPolicy
Set-HostedContentFilterPolicy -Identity Default -HighConfidencePhishAction Quarantine -HighConfidencePhishQuarantineTag AdminOnlyAccessPolicy
Set-HostedContentFilterPolicy -Identity Default -BulkSpamAction MoveToJmf -QuarantineRetentionPeriod 30

#Anti-spam outbound policy (Default)
Set-HostedOutboundSpamFilterPolicy -Identity Default -RecipientLimitExternalPerHour 500 -RecipientLimitInternalPerHour 1000 -RecipientLimitPerDay 1000 -ActionWhenThresholdReached BlockUser
Set-HostedOutboundSpamFilterPolicy -Identity Default -NotifyOutboundSpam $True -NotifyOutboundSpamRecipients $email 
Set-HostedOutboundSpamFilterPolicy -Identity Default -BccSuspiciousOutboundMail $True -BccSuspiciousOutboundAdditionalRecipients $email


#Office365 AntiPhish Default (Default)
#https://security.microsoft.com/antiphishing
#Get-AntiPhishPolicy -Identity "Office365 AntiPhish Default"
#Phishing threshold & protection
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishThresholdLevel 2
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableOrganizationDomainsProtection $true -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction Quarantine -EnableTargetedUserProtection $true -TargetedUserProtectionAction Quarantine -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction Quarantine -EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true

#Action
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -TargetedUserQuarantineTag DefaultFullAccessPolicy -MailboxIntelligenceQuarantineTag DefaultFullAccessPolicy -TargetedDomainQuarantineTag DefaultFullAccessPolicy -SpoofQuarantineTag DefaultFullAccessPolicy

#Safety tips & indicators
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableSimilarUsersSafetyTips $True -EnableSimilarDomainsSafetyTips $True -EnableUnusualCharactersSafetyTips $True -EnableViaTag $True -EnableUnauthenticatedSender $True


#Anti-Malware
#https://security.microsoft.com/antimalwarev2
Set-MalwareFilterPolicy -Identity Default -EnableInternalSenderNotifications $False -EnableExternalSenderNotifications $False
Set-MalwareFilterPolicy -Identity Default -EnableInternalSenderAdminNotifications $True -EnableExternalSenderAdminNotifications $True
Set-MalwareFilterPolicy -Identity Default -InternalSenderAdminAddress $email -ExternalSenderAdminAddress $email
Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $True
Set-MalwareFilterPolicy -Identity Default -FileTypes "ade","adp","ani","bas","bat","chm","cmd","com","cpl","crt","hlp","ht","hta","inf","ins","isp","job","js","jse","lnk","mda","mdb","mde","mdz","msc","msi","msp","mst","pcd","reg","scr","sct","shs","url","vb","vbe","vbs","wsc","wsf","wsh","exe","pif"

#Safe Links
#https://security.microsoft.com/safelinksv2
#Get-AtpPolicyForO365
New-SafeLinksPolicy -Name "Safe-Links-Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -TrackClicks $true -ScanUrls $true -EnableForInternalSenders $true -DeliverMessageAfterScan $true -DisableUrlRewrite $False -EnableOrganizationBranding $False
Set-SafeLinksPolicy -Identity "Safe-Links-Policy" -AllowClickThrough $False
New-SafeLinksRule -Name "Safe-Links-Rule" -SafeLinksPolicy "Safe-Links-Policy" -Priority 0 -RecipientDomainIs $Domain_one,$Domain_two,$Domain_three

Set-AtpPolicyForO365 -TrackClicks $True -AllowClickThrough $False -EnableSafeLinksForO365Clients $True -EnableATPForSPOTeamsODB $True -EnableSafeDocs $True -AllowSafeDocsOpen $False


#Safe Attachments
#https://security.microsoft.com/safeattachmentv2
New-SafeAttachmentPolicy -Name Safe-Attachment-Policy -Enable $true -Redirect $true  -Action Block -RedirectAddress $email
New-SafeAttachmentRule -Name "Safe-Attachment-Policy" -SafeAttachmentPolicy "Safe-Attachment-Policy" -Priority 0 -RecipientDomainIs $Domain_one,$Domain_two,$Domain_three

#Enable the Unified Audit Log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

Get-ORCAReport

Remove-item .\credential.txt

#KAYNAKLAR
#Antispam-Antimalware
#https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#antispam-antimalware
#Defender-for-Office-365
#https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#defender-for-office-365