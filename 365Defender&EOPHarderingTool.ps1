Write-Host "Mehmet PATLAKYİĞİT | Office Apps & Services MVP" -ForegroundColor blue
Write-Host "https://www.parlakyigit.net/" -ForegroundColor blue
Write-Host "Twitter:@mparlakyigit" -ForegroundColor blue

<#
.NOTE
Bu PowerShell betiği ORCA raporu çıktısına göre Exchange Online Protection ve Microsoft Defender for Office 365 ürünlerinin sıkılaştırılmasını otomatize 
etmektedir.
#>

<#
.NOTE
Düzenleme yapılmayan rapor sonuçları
- DKIM 
- ip adres WhiteList ve e-mail ve domain WhiteListe
#>


Set-ExecutionPolicy Unrestricted
Install-Module -Name ExchangeOnlineManagement
Get-ExecutionPolicy
Import-Module ExchangeOnlineManagement
Write-Host "Exchange Online Servisine Bağlandı." -ForegroundColor Green
Install-Module ORCA
Get-ORCAReport

$Domain_one = "mparlakyigit.onmicrosoft.com"
$Domain_two = "ozcanmandiraci.com"
$Domain_three = "parlakyigit.net"
$email = "security@parlakyigit.net"

#Yeni Paylaşılan Posta Kutusu oluşturulur.
New-Mailbox -Shared -Name "Security Team" -DisplayName "Security Team" -Alias security


#External PostMaster E-Mail Adress değişimi yapmaktadır. 
#Get-TransportConfig | Format-List ExternalPostmasterAddress
Set-TransportConfig -ExternalPostmasterAddress $email

#Quarantine Policy
#Get-QuarantinePolicy | Format-Table Name
#Limitli Erişim-Alıcılar karantinaya alınan öğeleri görüntüleyebilir.Serbest bırakamaz.
#https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/quarantine-policies?view=o365-worldwide#create-quarantine-policies-in-powershell
New-QuarantinePolicy -Name NotificationEnabledPolicy -EndUserQuarantinePermissionsValue 27 -EsnEnabled $true

#Anti-spam inbound policy (Default)
#https://security.microsoft.com/antispam
#Get-HostedContentFilterPolicy Default | Format-List
set-HostedContentFilterPolicy -Identity Default -MarkAsSpamBulkMail on -BulkThreshold 6
Set-HostedContentFilterPolicy -Identity Default -EnableEndUserSpamNotifications $True
Set-HostedContentFilterPolicy -Identity Default -EndUserSpamNotificationFrequency 3
#Get-HostedContentFilterPolicy | Format-List Name,*SpamAction,HighConfidencePhishAction,*QuarantineTag
#Get-AntiPhishPolicy | Format-List Name,Enable*Intelligence,Enable*Protection,*Action,*QuarantineTag
Set-HostedContentFilterPolicy -Identity Default -SpamAction Quarantine -SpamQuarantineTag NotificationEnabledPolicy
Set-HostedContentFilterPolicy -Identity Default -HighConfidenceSpamAction Quarantine 
Set-HostedContentFilterPolicy -Identity Default -HighConfidenceSpamQuarantineTag NotificationEnabledPolicy

Set-HostedContentFilterPolicy -Identity Default -PhishSpamAction Quarantine -PhishQuarantineTag NotificationEnabledPolicy
Set-HostedContentFilterPolicy -Identity Default -HighConfidencePhishAction Quarantine -HighConfidencePhishQuarantineTag AdminOnlyAccessPolicy
Set-HostedContentFilterPolicy -Identity Default -BulkSpamAction MoveToJmf -QuarantineRetentionPeriod 30

#Anti-spam outbound policy (Default)
#Get-HostedOutboundSpamFilterPolicy Default | Format-List
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
Set-MalwareFilterPolicy -Identity Default -EnableInternalSenderAdminNotifications $False -EnableExternalSenderAdminNotifications $False
#Set-MalwareFilterPolicy -Identity Default -InternalSenderAdminAddress $email -ExternalSenderAdminAddress $email
Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $True
Set-MalwareFilterPolicy -Identity Default -FileTypes "ade","adp","ani","bas","bat","chm","cmd","com","cpl","crt","hlp","ht","hta","inf","ins","isp","job","js","jse","lnk","mda","mdb","mde","mdz","msc","msi","msp","mst","pcd","reg","scr","sct","shs","url","vb","vbe","vbs","wsc","wsf","wsh","exe","pif"

#Safe Links
#https://security.microsoft.com/safelinksv2
#Get-AtpPolicyForO365
New-SafeLinksPolicy -Name "Safe-Links-Policy" -EnableSafeLinksForTeams $true -TrackClicks $true -ScanUrls $true -EnableForInternalSenders $true -DeliverMessageAfterScan $true -DisableUrlRewrite $False -EnableOrganizationBranding $False
Set-SafeLinksPolicy -Identity "Safe-Links-Policy" -AllowClickThrough $False
#Set-SafeLinksPolicy  -Identity "Safe-Links-Policy" -DoNotAllowClickThrough $true -DoNotTrackUserClicks $False
New-SafeLinksRule -Name "Safe-Links-Rule" -SafeLinksPolicy "Safe-Links-Policy" -Priority 0 -RecipientDomainIs $Domain_one,$Domain_two,$Domain_three

Set-AtpPolicyForO365 -TrackClicks $True -AllowClickThrough $False -EnableSafeLinksForO365Clients $True -EnableATPForSPOTeamsODB $True -EnableSafeDocs $True -AllowSafeDocsOpen $False
Set-SafeLinksPolicy -Identity "Built-In Protection Policy" -DoNotAllowClickThrough $true
#WARNING: All Built In Protection policy settings will be controlled by Microsoft.

#Safe Attachments
#https://security.microsoft.com/safeattachmentv2
New-SafeAttachmentPolicy -Name Safe-Attachment-Policy -Enable $true -Redirect $true  -Action Block -RedirectAddress $email
New-SafeAttachmentRule -Name "Safe-Attachment-Policy" -SafeAttachmentPolicy "Safe-Attachment-Policy" -Priority 0 -RecipientDomainIs $Domain_one,$Domain_two,$Domain_three

#Enable the Unified Audit Log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

#Enable Modern Authentication
#Get-OrganizationConfig | Format-Table Name,OAuth* -Auto
Set-OrganizationConfig -OAuth2ClientProfileEnabled $true


#TLS 1.2 öncesini kullanan uygulamalar içindir.False çekildiğinde 1.2  TLS kullanan uygulamalar ve yazıcılar SMTP mail gönderiminde sıkıntı yaşayabilirler.
#Bu tercih opsiyoneldir.
#Set-TransportConfig -AllowLegacyTLSClients $False



Get-ORCAReport


#KAYNAKLAR
#Antispam-Antimalware
#https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#antispam-antimalware
#Defender-for-Office-365
#https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#defender-for-office-365
