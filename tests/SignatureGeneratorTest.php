<?php

date_default_timezone_set('UTC');

use Kunststube\CSRFP\SignatureGenerator;

require_once 'SignatureGenerator.php';


class SignatureGeneratorTest extends PHPUnit_Framework_TestCase {

	protected function secret() {
		return sha1(mt_rand());
	}

	public function testSimpleToken() {
		$secret = $this->secret();

		$sg = new SignatureGenerator($secret);
		$signature = $sg->getSignature();

		$this->assertStringMatchesFormat('%s', $signature);
		$this->assertGreaterThan(10, strlen($signature));
		$this->assertNotContains($secret, $signature);
	}

	public function testIncludedValues() {
		$sg = new SignatureGenerator($this->secret());
		$sg->addValue('foo');
		$sg->addValue('bar');
		$sg->addValue('baz');
		$this->assertStringMatchesFormat('%s', $sg->getSignature());
	}

	public function testIncludedKeyValues() {
		$sg = new SignatureGenerator($this->secret());
		$sg->addKeyValue('foo', 'bar');
		$sg->addKeyValue('baz', 42);
		$this->assertStringMatchesFormat('%s', $sg->getSignature());
	}

	public function testSignatureRoundtripValidation() {
		$sg = new SignatureGenerator($this->secret());
		$signature = $sg->getSignature();
		$this->assertTrue($sg->validateSignature($signature));
	}

	public function testSignatureRoundtripValidationWithData() {
		$sg = new SignatureGenerator($this->secret());
		$sg->addValue('foo');
		$sg->addKeyValue('bar', 'baz');
		$signature = $sg->getSignature();
		$this->assertTrue($sg->validateSignature($signature));
	}

	public function testSeparateSignatureValidation() {
		$secret = $this->secret();

		$sg1 = new SignatureGenerator($secret);
		$signature = $sg1->getSignature();

		$sg2 = new SignatureGenerator($secret);
		$this->assertTrue($sg2->validateSignature($signature));
	}

	public function testSeparateSignatureValidationWithData() {
		$secret = $this->secret();

		$sg1 = new SignatureGenerator($secret);
		$sg1->addValue('foo');
		$sg1->addKeyValue('bar', 'baz');
		$signature = $sg1->getSignature();

		$sg2 = new SignatureGenerator($secret);
		$sg2->addValue('foo');
		$sg2->addKeyValue('bar', 'baz');
		$this->assertTrue($sg2->validateSignature($signature));
	}

	public function testSimpleValidationFail() {
		$sg = new SignatureGenerator($this->secret());
		$signature = $sg->getSignature();
		$fakeSignature = str_rot13($signature);
		$this->assertFalse($sg->validateSignature($fakeSignature));
	}

	public function testValidationFailWithData() {
		$sg = new SignatureGenerator($this->secret());
		$sg->addValue('foo');
		$sg->addKeyValue('bar', 'baz');
		$signature = $sg->getSignature();
		$fakeSignature = str_rot13($signature);
		$this->assertFalse($sg->validateSignature($fakeSignature));
	}

	public function testReinstantiatedValidationFailWithData() {
		$secret = $this->secret();
		
		$sg1 = new SignatureGenerator($secret);
		$sg1->addValue('foo');
		$sg1->addKeyValue('bar', 'baz');
		
		$signature = $sg1->getSignature();
		$fakeSignature = str_rot13($signature);

		$sg2 = new SignatureGenerator($secret);
		$sg2->addValue('foo');
		$sg2->addKeyValue('bar', 'baz');

		$this->assertFalse($sg2->validateSignature($fakeSignature));
	}

	/**
     * @expectedException InvalidArgumentException
     */
	public function testSignatureFormatFail() {
		$sg = new SignatureGenerator($this->secret());
		$fakeSignature = sha1(mt_rand());
		$sg->validateSignature($fakeSignature);
	}

	public function testTokenTimeoutFail() {
		$sg = new SignatureGenerator($this->secret());
		$signature = $sg->getSignature();
		$sg->setValidityWindow(time() + 10);
		$this->assertFalse($sg->validateSignature($signature));
	}

	public function testInfiniteTokenValidity() {
		$sg = new SignatureGenerator($this->secret());
		$signature = $sg->getSignature();
		$sg->setValidityWindow(0);
		$this->assertTrue($sg->validateSignature($signature));
	}

	public function testTimestampFutzingFail() {
		$sg = new SignatureGenerator($this->secret());
		$signature = $sg->getSignature();
		$this->assertStringMatchesFormat('%d%s', $signature);
		
		$fakeSignature = preg_replace('/^\d+/', time() + 1000, $signature);
		$sg->setValidityWindow(time() + 100);
		$this->assertFalse($sg->validateSignature($fakeSignature));
	}

	public function testOrderOfAddedData() {
		$secret = $this->secret();

		$sg1 = new SignatureGenerator($secret);
		$sg1->addValue('foo');
		$sg1->addValue('bar');
		$sg1->addKeyValue('baz', 42);
		
		$sg2 = new SignatureGenerator($secret);
		$sg2->addKeyValue('baz', 42);
		$sg2->addValue('bar');
		$sg2->addValue('foo');

		$this->assertTrue($sg2->validateSignature($sg1->getSignature()));
	}

	public function testSameDataDifferentSignature() {
		$secret = $this->secret();

		$sg1 = new SignatureGenerator($secret);
		$sg1->addValue('foo');
		$sg1->addValue('bar');
		$sg1->addKeyValue('baz', 42);

		$sg2 = new SignatureGenerator($secret);
		$sg2->addValue('foo');
		$sg2->addValue('bar');
		$sg2->addKeyValue('baz', 42);

		$this->assertNotEquals($sg1->getSignature(), $sg2->getSignature());
	}

}
