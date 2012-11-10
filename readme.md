Kunststube\CSRFP - Cross Site Request Forgery Protection
========================================================

This library is a simple signature generator to protect form submissions from cross site request forgery, using a signed token. It does not require server-side storage of valid tokens and is thereby stateless.

Context
-------

Cross site request forgery can be subverted by including a token in each form which is hard to replicate by an attacker. Upon receiving a form submission, the token is checked for validity and the submitted data is deemed valid or invalid based on the validity of the token.

One implementation of this idea is to generate a random value, store it server-side in the user's session and in a hidden field in the form, then upon form submission check if the submitted value is identical to the value stored in the session. This approach has the drawback of requiring server-side state and storage space. The implementation also becomes slightly more complex when wanting to allow the user to open several forms/tabs at once, possibly allowing several valid tokens to be in play at the same time.

The Kunststube\CSRFP library uses a signature approach. A randomly generated token is signed using a secret, which is statically stored on the server. The random token and its signed version are together embedded into the form as a signature. Upon receiving the form submission, the signature is generated again from the submitted token and the known secret and compared to the submitted signature. The signature should only be valid if the entity that generated it knows the secret, proving that the signed token originally came from the server itself.

Simple usage
------------

```php
<?php
    
    require_once 'CSRFP/SignatureGenerator.php';

    $secret = '948thksehbf23fnoug2p4g2o...'; // well chosen secret

    $signer = new Kunststube\CSRFP\SignatureGenerator($secret);

    if ($_POST) {
        if (!$signer->validateSignature($_POST['_token'])) {
            header('HTTP/1.0 400 Bad Request');
            exit;
        }
    }

?>

<form action="" method="post">
    <?php printf('<input type="hidden" name="_token" value="%s">',
                 htmlspecialchars($signer->getSignature())); ?>
    ...
    <input type="submit" value="Submit">
</form>
```

The `SignatureGenerator` needs the be instantiated with the same secret every time. To generate a signed token, simply call `SignatureGenerator::getSignature` and embed the value into a hidden form field. Upon form submission, validate this token using `SignatureGenerator::validateSignature`.

Time limited validity
---------------------

The signature includes a timestamp of when it was generated. This can be used to expire it after some time. The timestamp is part of the signature generation process and cannot be altered. By default the signature expires after a few hours (see `SignatureGenerator::$validityWindow` for default value). You can set your own validity window using `SignatureGenerator::setValidityWindow`:

```php
$signer->setValidityWindow(time() - 3600);
$signer->setValidityWindow('-1 hour');
$signer->setValidityWindow(new DateTime('-1 hour'));
```

The method accepts an integer UNIX timestamp, a string which will be evaluated by `strtotime` or an instance of `DateTime`. Any signature older than the set timestamp will be regarded as expired. The default timeout should present a reasonable value which makes sure signatures do expire eventually, without frustrating slow users. Adjust it to make it tighter or more relaxed based on your needs.

Adding data
-----------

The signature can additionally be used to protect against form field injection and/or can be tied to a specific user. Data can be added to the signature generation process using `SignatureGenerator::addValue` and `SignatureGenerator::addKeyValue`:

```php
$signer->addValue('foo');
$signer->addKeyValue('bar', 'baz');
```

The signature will only be valid if the same data was added when the token was generated and when it is being validated. To protect against form field injection you should add the names of all `<input>` elements which you expect to receive in the submitted form using `SignatureGenerator::addValue`. Any additional data you want to tie to the signature, like the user id, should be added using `SignatureGenerator::addKeyValue`.

For example, when generating the token:

```php
<?php
    $signer = new Kunststube\CSRFP\SignatureGenerator($secret);
    
    // including user id in signature
    // 'userid' is an arbitrarily chosen key name
    $signer->addKeyValue('userid', $_SESSION['User']['id']);
    
    // including names of valid form fields in signature
    $signer->addValue('firstname');
    $signer->addValue('lastname');
?>

<form action="" method="post">
    <?php printf('<input type="hidden" name="_token" value="%s">',
                 htmlspecialchars($signer->getSignature())); ?>
    <input type="text" name="firstname">
    <input type="text" name="lastname">
    <input type="submit" value="Submit">
</form>
```

When validating the token, use the submitted form fields as part of the validation:

```php
$signer = new Kunststube\CSRFP\SignatureGenerator($secret);

// including user id in signature validation
$signer->addKeyValue('userid', $_SESSION['User']['id']);

// including submitted form fields in signature validation
foreach (array_keys($_POST) as $key) {
    // not adding '_token' itself
    if ($key == '_token') {
        continue;
    }
    $signer->addValue($key);
}

if (!$signer->validateSignature($_POST['_token'])) {
    // error
}
```

This way, if any fields which were not part of the original signature are submitted with the form, it will not validate. Take care if you're dynamically adding form fields using Javascript.

### Note

The drawback of adding form fields is that the same form fields need to be added when generating the signature and when validating it. This requires to keep the list of expected and actual form fields in sync, which can quickly lead to code duplication if not handled properly. For best results I'd recommend using this library as part of a larger form generating function/class/library which handles this.

Signature format
----------------

The generated signature has the following format:

    1352582467:PdyfgHNZt...1Uqg==:94KNdWzg4...7iwHw==
    timestamp |   random token   |   signed token

The random token and signed token are base64 encoded data. The total signature is about 188 bytes in length by default.

The signature format by default is, simplified:

    timestamp + ":" + token + ":" + signed token

where

    timestamp    = unsigned integer
    token        = base64 encoded random value
    signed token = base64 encoded hash
    hash         = HMAC_SHA512(timestamp + token + data, secret)
    data         = all added values

The `data` is sorted, so the order in which the values are added does not matter. The above description omits technical details on which exact format the data is put in for hashing, please consult the source code.

Crypto provider
---------------

An alternative `CryptoProvider`, which provides a source of randomness and the hashing algorithm, can be passed upon instantiating `SignatureGenerator` as the second argument to the constructor. Consult `ICryptoProvider.php` and `CryptoProvider.php`.

PSR-0
-----

The repository is organized so its contents can be dumped into a folder `Kunststube/CSRFP/` and the naming be PSR-0 compliant.

Warning
-------

Use security related software only if you have vetted it and trust its premise and implementation, or if you trust the community to have vetted it and deemed it secure. While the author is fairly confident that the software works as described above, it has not been critically vetted by peers just yet. The author does not make any promises or guarantees as to the function of the software.

Information
-----------

Version: 0.1 (initial release)  
Author:  David Zentgraf  
Contact: csrfp@kunststube.net  
License: Public Domain

