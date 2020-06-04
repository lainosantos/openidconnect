<?php
/**
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 *
 * @copyright Copyright (c) 2020, ownCloud GmbH
 * @license GPL-2.0
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\OpenIdConnect\Tests\Unit\Service;

use OC\HintException;
use OC\User\LoginException;
use OCA\OpenIdConnect\Client;
use OCA\OpenIdConnect\Service\UserLookupService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IConfig;
use OCP\ILogger;
use OCP\Mail\IMailer;
use OCP\Security\ISecureRandom;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class UserLookupServiceTest extends TestCase {

	/**
	 * @var UserLookupService
	 */
	private $userLookup;
    /**
     * @var IL10N
     */
    private $l10n;
    /**
     * @var MockObject | IConfig
     */
    private $config;
    /**
     * @var MockObject | ILogger
     */
    private $log;
    /**
     * @var MockObject | IMailer
     */
    private $mailer;
    /**
     * @var MockObject | ISecureRandom
     */
    private $secureRandom;
    /**
     * @var MockObject | EventDispatcherInterface
     */
    private $eventDispatcher;
    /**
     * @var \OC_Defaults
     */
    private $defaults;
    /**
     * @var ITimeFactory
     */
    protected $timeFactory;
    /**
     * @var IURLGenerator
     */
    private $urlGenerator;

	protected function setUp(): void {
		parent::setUp();
        $this->config = $this->createMock(IConfig::class);
        $this->log = $this->createMock(ILogger::class);
        $this->mailer = $this->createMock(IMailer::class);
        $this->secureRandom = $this->createMock(ISecureRandom::class);
        $this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);
		$this->client = $this->createMock(Client::class);
		$this->manager = $this->createMock(IUserManager::class);
        $this->l10n = $this->createMock(IL10N::class);
        $this->defaults = $this->createMock(\OC_Defaults::class);
        $this->timeFactory = $this->createMock(ITimeFactory::class);
        $this->urlGenerator = $this->createMock(IURLGenerator::class);
        $fromMailAddress = 'no-reply@example.com';

		$this->userLookup = new UserLookupService($this->manager, $this->client, $this->l10n, $this->config,
            $this->secureRandom, $this->log, $this->defaults,  $this->mailer, $this->timeFactory, $fromMailAddress,
            $this->urlGenerator, $this->eventDispatcher);
	}

	public function testNotConfigured(): void {
		$this->expectException(HintException::class);
		$this->expectExceptionMessage('Configuration issue in openidconnect app');

		$this->userLookup->lookupUser(null);
	}

	public function testLookupByEMailNotFound(): void {
		$this->expectException(LoginException::class);
		$this->expectExceptionMessage('User foo@example.com is not known.');
		$this->client->method('getOpenIdConfig')->willReturn([]);
		$this->userLookup->lookupUser((object)['email' => 'foo@example.com']);
	}

	public function testLookupByEMailNotUnique(): void {
		$this->expectException(LoginException::class);
		$this->expectExceptionMessage('foo@example.com is not unique.');
		$this->client->method('getOpenIdConfig')->willReturn([]);
		$this->manager->method('getByEmail')->willReturn([1, 2]);
		$this->userLookup->lookupUser((object)['email' => 'foo@example.com']);
	}

	public function testLookupByEMail(): void {
		$this->client->method('getOpenIdConfig')->willReturn([]);
		$user = $this->createMock(IUser::class);
		$this->manager->method('getByEmail')->willReturn([$user]);
		$return = $this->userLookup->lookupUser((object)['email' => 'foo@example.com']);
		self::assertEquals($user, $return);
	}

	public function testLookupByUserIdNotFound(): void {
		$this->expectException(LoginException::class);
		$this->expectExceptionMessage('User alice is not known.');
		$this->client->method('getOpenIdConfig')->willReturn(['mode' => 'userid', 'search-attribute' => 'preferred_username']);
		$this->userLookup->lookupUser((object)['preferred_username' => 'alice']);
	}

	public function testLookupByUserId(): void {
		$this->client->method('getOpenIdConfig')->willReturn(['mode' => 'userid', 'search-attribute' => 'preferred_username']);
		$user = $this->createMock(IUser::class);
		$this->manager->method('get')->willReturn($user);
		$return = $this->userLookup->lookupUser((object)['preferred_username' => 'alice']);
		self::assertEquals($user, $return);
	}

    public function testImportLookupByUserId(): void {
        $this->client->method('getOpenIdConfig')->willReturn([
            'mode' => 'userid',
            'search-attribute' => 'preferred_username',
            'import' => [
                'enabled' => true,
                'uid-attribute' => 'preferred_username',
                'email-attribute' => 'email',
                'display-name-attribute' => 'full_name',
            ],
        ]);
        $user = $this->createMock(IUser::class);
        $this->manager->method('get')->willReturn(null);
        $this->manager->method('createUser')->willReturn($user);
        $this->mailer->method('validateMailAddress')->willReturn(true);
        $return = $this->userLookup->lookupUser((object)[
            'preferred_username' => 'alice',
            'email' => 'foo@example.com',
            'full_name' => 'alice',
        ]);
        self::assertEquals($user, $return);
    }

    public function testImportLookupByEMail(): void {
        $this->client->method('getOpenIdConfig')->willReturn([
            'search-attribute' => 'email',
            'import' => [
                'enabled' => true,
                'uid-attribute' => 'preferred_username',
                'email-attribute' => 'email',
                'display-name-attribute' => 'full_name',
            ],
        ]);
        $user = $this->createMock(IUser::class);
        $this->manager->method('getByEmail')->willReturn(null);
        $this->manager->method('createUser')->willReturn($user);
        $this->mailer->method('validateMailAddress')->willReturn(true);
        $return = $this->userLookup->lookupUser((object)[
            'preferred_username' => 'alice',
            'email' => 'foo@example.com',
            'full_name' => 'alice',
        ]);
        self::assertEquals($user, $return);
    }

    public function testImportInvalidEMail(): void {
        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('Invalid mail address.');
        $this->client->method('getOpenIdConfig')->willReturn([
            'mode' => 'userid',
            'search-attribute' => 'preferred_username',
            'import' => [
                'enabled' => true,
                'uid-attribute' => 'preferred_username',
                'email-attribute' => 'email',
                'display-name-attribute' => 'full_name',
            ],
        ]);
        $this->manager->method('get')->willReturn(null);
        $this->mailer->method('validateMailAddress')->willReturn(false);
        $this->userLookup->lookupUser((object)[
            'preferred_username' => 'alice',
            'email' => 'foo',
            'full_name' => 'alice',
        ]);
    }

    public function testImportCreationException(): void {
        $this->expectException(LoginException::class);
        $this->expectExceptionMessage("Can't import new user from openid provider.");
        $this->client->method('getOpenIdConfig')->willReturn([
            'mode' => 'userid',
            'search-attribute' => 'preferred_username',
            'import' => [
                'enabled' => true,
                'uid-attribute' => 'preferred_username',
                'email-attribute' => 'email',
                'display-name-attribute' => 'full_name',
            ],
        ]);
        $this->mailer->method('validateMailAddress')->willReturn(true);
        $this->manager->method('createUser')->will($this->throwException(new \Exception()));
        $this->userLookup->lookupUser((object)[
            'preferred_username' => 'alice',
            'email' => 'foo',
            'full_name' => 'alice',
        ]);
    }
}
