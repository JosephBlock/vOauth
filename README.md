# vOauth
vOauth v1
Example in test/v.php


```php
//set up vOauth
$v=new vOauth();
/*
 * Change values to what you need
 * scopes are set as constants
*/
$v->setClient("Your client here");
$v->setSecret("Your secret here");
$v->addScope(array("Add scopes here"));
$v->setRedirect("redirect URL here");
```
