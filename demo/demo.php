<?php
    
    require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . 'SignatureGenerator.php';

    $secret = '948thksehbf23fnoug2p4g2o...'; // well chosen secret

    $signer = new Kunststube\CSRFP\SignatureGenerator($secret);

    $message = null;

    if ($_POST) {
        if (!$signer->validateSignature($_POST['_token'])) {
            header('HTTP/1.0 400 Bad Request');
            $message = 'Token INVALID.';
        } else {
            $message = 'Form submission ok.';
        }
    }

?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Kunststube\CSRFP Demo</title>
    </head>
    <body>

        <?php if ($message) : ?>
            <p><strong><?php echo $message; ?></strong></p>
        <?php endif; ?>

        <form action="" method="post">
            <?php printf('<input type="hidden" name="_token" value="%s">', htmlspecialchars($signer->getSignature())); ?>
            <p>Submitting this form as is should simply output a success message.</p>
            <p>Try futzing around with the hidden token in the DOM Inspector and see it fail.</p>
            <input type="submit" value="Try it">
        </form>

    </body>
</html>
