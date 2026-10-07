#Requires -Version 5.1
<# Run on any relying party (elevated). Drops cached CRLs and forces chain-engine resync so the next
   validation downloads the current CRL instead of trusting a cached one until its NextUpdate. #>
'== Cached CRL objects before flush'
certutil -urlcache crl | Select-String '\.crl'
certutil -urlcache crl delete | Select-String 'deleted|entries'
certutil -setreg chain\ChainCacheResyncFiletime '@now' | Select-String 'completed'
