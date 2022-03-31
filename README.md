# Exchange Online Protection &amp; Microsoft Defender For Office 365 Hardering Tool
Bu PowerShell betiği Office 365 Recommended Configuration Analyzer (ORCA) raporu çıktısına göre Exchange Online Protection ve Microsoft Defender for Office 365 ürünlerinin sıkılaştırılmasını otomatize etmektedir.

İhtiyaç duyulan lisanslar
- Exchange Online Plan 1 veya 2 (Bu hizmetler içerisinde hali hazırda Exchange Online Protection gelmektedir.)
- Microosft Defender for Office 365 Plan 1 veya 2

![2](https://user-images.githubusercontent.com/53214224/161149367-f074665d-63cc-4ae0-8ee9-47bb1249bd65.png)

Öncelikle yapmanız gereken mavi kare içerisindeki $ (değişkenleri) kendi organizasyonunuza göre doldurmak olacaktır. (.onmicrosoft.com) domain isimlerinizide eklerseniz. Daha temiz bir sonuç alabilirsiniz.

Not: $email değişkeni içerisinde belirtilen mail adresi yeni bir shared MailBox için kullanılmaktadır. Sonrasında gelen bildiğimleri görüntüleyecek kişilerin ilgili mailbox üzerinde yetkilerinin verilmesi gerekmektedir.

![1](https://user-images.githubusercontent.com/53214224/161149465-986a5fad-dfaf-4dda-bccf-62a38f39a4fb.png)

- PowerShell betiğini çalıştırabilmek için öncelikle PowerShell uygulamanızı yönetici olarak çalıştırınız.
- cd 365Defender&EOPHarderingTool.ps1 dosyasının bulunduğu dizine geçiniz.
- ./365Defender&EOPHarderingTool.ps1 şeklinde betiği çalıştırınız.
- Sizden istenilen Office 365 Global admin yetkisi olan bir kullanıcı adı ve parolasını giriniz. (İlgili kullanıcının Exchange Administrator yetkisi olduğundan emin olunuz.)

Not: Bu PowerShell betiğini çalıştırırken ne yaptığınızı öncelikle bilmeniz gerekmektedir. Aksi taktirde bir çok kargaşaya neden olabilirsiniz.
