<?php
declare(strict_types=1);
use Rotexsoft\CSRF;

/**
 * Description of ArraysCollectionTest
 *
 * @author Rotimi Ade
 */
class CSRFTest extends \PHPUnit\Framework\TestCase{
    
    protected function setUp(): void { 
        
        parent::setUp();
        session_start();
    }

    protected function getNewCsrfObject(
        string $keyNameInSession = 'csrf-lib',
        string $inputName = 'key-awesome',
        int $hashTime2Live = 0,
        int $hashSize = 64
    ): CSRF {
        return new class($keyNameInSession, $inputName, $hashTime2Live, $hashSize) extends CSRF {
            
            public function __get(string $propertyName): mixed {
                
                // Expose protected & private properties
                if(property_exists($this, $propertyName)) { return $this->{$propertyName}; }
            }
            
            public function __call(string $methodName, array $arguments): mixed {
                
                // Expose protected & private methods
                if(method_exists($this, $methodName)) { return $this->{$methodName}(...$arguments); }
            }
        }; 
    }
    
    /**
     * @runInSeparateProcess
     */
    public function testThatValidateWorksAsExpected() {

        $csrfObj = $this->getNewCsrfObject();
        
        //////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////
        // public function validate(string $context = '', string|null $hash = null): bool
        // $context === '' & $hash === null
        //////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////
        
        // no hash in session,
        // no hash in $_GET,
        // no hash in $_POST,
        // no hash passed to validate
        self::assertFalse($csrfObj->validate());
        
        // no hash in session,
        // hash in $_GET,
        // no hash in $_POST,
        // no hash passed to validate
        $_GET[$csrfObj->inputName] = 'some stuff';
        self::assertFalse($csrfObj->validate());
        unset($_GET[$csrfObj->inputName]);
        
        // no hash in session,
        // no hash in $_GET,
        // hash in $_POST,
        // no hash passed to validate
        $_POST[$csrfObj->inputName] = 'some stuff';
        self::assertFalse($csrfObj->validate());
        unset($_POST[$csrfObj->inputName]);
        
        // hash in session,
        // hash in $_GET, 
        // no hash in $_POST,
        // no hash passed to validate
        $hash1 = $csrfObj->string();
        $_GET[$csrfObj->inputName] = $hash1;
        self::assertTrue($csrfObj->validate());
        self::assertFalse($csrfObj->validate('', 'non-existent-hash'));
        self::assertFalse($csrfObj->validate('a-context')); //hash isn't associated with this context
        
        $hash1b = $csrfObj->string('a-context');
        $_GET[$csrfObj->inputName] = $hash1b;
        self::assertTrue($csrfObj->validate('a-context'));  // hash is associated with this context and is valid
                                                            // and after passing validation hash is removed from
                                                            // list of hashes associated with the specified context

        self::assertFalse($csrfObj->validate('a-context')); // since hash has been removed validation would no longer pass
        unset($_GET[$csrfObj->inputName]);
        
        // hash in session,
        // no hash in $_GET,
        // hash in $_POST,
        // no hash passed to validate
        $hash2 = $csrfObj->string();
        $_POST[$csrfObj->inputName] = $hash2;
        self::assertTrue($csrfObj->validate());
        self::assertFalse($csrfObj->validate('a-context')); //hash isn't associated with this context
        $hash2b = $csrfObj->string('a-context');
        $_POST[$csrfObj->inputName] = $hash2b;
        self::assertTrue($csrfObj->validate('a-context')); //hash is associated with this context
        unset($_POST[$csrfObj->inputName]);
    }
    
    /**
     * @runInSeparateProcess
     */
    public function testThatSaveWorksAsExpected() {
        
        $keyNameInSession = 'da-keyzzle';
        $csrfObj = $this->getNewCsrfObject(keyNameInSession: $keyNameInSession);        
        $expectedSessionEntry = serialize($csrfObj->hashes);
        
        self::assertSame($csrfObj, $csrfObj->save());
        self::assertArrayHasKey($keyNameInSession, $_SESSION);
        self::assertEquals($expectedSessionEntry, $_SESSION[$keyNameInSession]);
    }
    
    /**
     * @runInSeparateProcess
     */
    public function testThatClearHashesWorksAsExpected() {
        
        //////////////////////////////////////////////////
        // new instances of \Rotexsoft\CSRF with no hashes
        //////////////////////////////////////////////////
        self::assertEquals([], $this->getNewCsrfObject()->hashes);
        
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('', 0));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('', -1));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('', -2));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('', 1));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('', 2));
        
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('non-empty-context', 0));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('non-empty-context', -1));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('non-empty-context', -2));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('non-empty-context', 1));
        self::assertEquals(0, $this->getNewCsrfObject()->clearHashes('non-empty-context', 2));
        
        ///////////////////////////////////////////////////
        // new instances of \Rotexsoft\CSRF with 5 hashes
        ///////////////////////////////////////////////////
        $csrfObj = $this->getNewCsrfObject();
        self::assertEquals([], $csrfObj->hashes);
        
        // create 5 hashes in the empty string context
        $emptyStringContextHash1 = $csrfObj->string('');
        $emptyStringContextHash2 = $csrfObj->string('');
        $emptyStringContextHash3 = $csrfObj->string('');
        $emptyStringContextHash4 = $csrfObj->string('');
        $emptyStringContextHash5 = $csrfObj->string('');

        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash3, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash4, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash5, $hashesForEmptyStringContext);
        
        self::assertEquals(3, $csrfObj->clearHashes('', 2)); // clear all but the last two hashes out of five
        
        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertNotContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash3, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash4, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash5, $hashesForEmptyStringContext);
        
        self::assertEquals(1, $csrfObj->clearHashes('', 1)); // clear all but the last one hash out of the two remaining hashes
        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertNotContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash3, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash4, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash5, $hashesForEmptyStringContext);
        
        self::assertEquals(1, $csrfObj->clearHashes('', 0)); // clear all the remaining hashes (in this case just one left)
        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertNotContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash3, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash4, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash5, $hashesForEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj->hashes);
        
        // add another 2 hashes
        $emptyStringContextHash1 = $csrfObj->string('');
        $emptyStringContextHash2 = $csrfObj->string('');

        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        
        self::assertEquals(2, $csrfObj->clearHashes('', -1)); // clear all the hashes (the two we just added)
        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertNotContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj->hashes);
        
        // add another 2 hashes
        $emptyStringContextHash1 = $csrfObj->string('');
        $emptyStringContextHash2 = $csrfObj->string('');

        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        
        self::assertEquals(2, $csrfObj->clearHashes('', -2)); // clear all the hashes (the two we just added)
        $hashesForEmptyStringContext = $csrfObj->getHashes('');
        self::assertNotContains($emptyStringContextHash1, $hashesForEmptyStringContext);
        self::assertNotContains($emptyStringContextHash2, $hashesForEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj->hashes);
        
        ////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////
        
        ///////////////////////////////////////////////////
        // Repeat Tests with non-empty context
        ///////////////////////////////////////////////////
        $csrfObj2 = $this->getNewCsrfObject();
        self::assertEquals([], $csrfObj2->hashes);
        
        $context = 'da-context';
		
        // create 5 hashes in the non-empty string context
        $nonEmptyStringContextHash1 = $csrfObj2->string($context);
        $nonEmptyStringContextHash2 = $csrfObj2->string($context);
        $nonEmptyStringContextHash3 = $csrfObj2->string($context);
        $nonEmptyStringContextHash4 = $csrfObj2->string($context);
        $nonEmptyStringContextHash5 = $csrfObj2->string($context);

        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
        
        self::assertEquals(3, $csrfObj2->clearHashes($context, 2)); // clear all but the last two hashes out of five
        
        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertNotContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
        
        self::assertEquals(1, $csrfObj2->clearHashes($context, 1)); // clear all but the last one hash out of the two remaining hashes
        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertNotContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
        
        self::assertEquals(1, $csrfObj2->clearHashes($context, 0)); // clear all the remaining hashes (in this case just one left)
        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertNotContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj2->hashes);
        
        // add another 2 hashes
        $nonEmptyStringContextHash1 = $csrfObj2->string($context);
        $nonEmptyStringContextHash2 = $csrfObj2->string($context);

        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        
        self::assertEquals(2, $csrfObj2->clearHashes($context, -1)); // clear all the hashes (the two we just added)
        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertNotContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj2->hashes);
        
        // add another 2 hashes
        $nonEmptyStringContextHash1 = $csrfObj2->string($context);
        $nonEmptyStringContextHash2 = $csrfObj2->string($context);

        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        
        self::assertEquals(2, $csrfObj2->clearHashes($context, -2)); // clear all the hashes (the two we just added)
        $hashesForNonEmptyStringContext = $csrfObj2->getHashes($context);
        self::assertNotContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertNotContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        
        //hashes should be empty at this point
        self::assertEquals([], $csrfObj2->hashes);
        
        ///////////////////////////////////////////////////
        // Repeat Tests with non-empty context
        ///////////////////////////////////////////////////
        $csrfObj3 = $this->getNewCsrfObject();
        self::assertEquals([], $csrfObj2->hashes);
        
        $context = 'da-context';
		
        // create 5 hashes in the non-empty string context
        $nonEmptyStringContextHash1 = $csrfObj3->string($context);
        $nonEmptyStringContextHash2 = $csrfObj3->string($context);
        $nonEmptyStringContextHash3 = $csrfObj3->string($context);
        $nonEmptyStringContextHash4 = $csrfObj3->string($context);
        $nonEmptyStringContextHash5 = $csrfObj3->string($context);

        $hashesForNonEmptyStringContext = $csrfObj3->getHashes($context);
        self::assertContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
        
        // trying to clear all hashes for a non-existent context should do nothing
        self::assertEquals(0, $csrfObj3->clearHashes('non-existing-context', 0));
        
        $hashesForNonEmptyStringContext = $csrfObj3->getHashes($context);
        self::assertContains($nonEmptyStringContextHash1, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash2, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash3, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash4, $hashesForNonEmptyStringContext);
        self::assertContains($nonEmptyStringContextHash5, $hashesForNonEmptyStringContext);
    }
}
