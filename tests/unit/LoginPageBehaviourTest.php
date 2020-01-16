<?php

namespace OCA\OpenIdConnect\Tests\Unit;

use OCA\OpenIdConnect\Logger;
use OCA\OpenIdConnect\LoginPageBehaviour;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class LoginPageBehaviourTest extends TestCase {

	/**
	 * @var MockObject | Logger
	 */
	private $logger;
	/**
	 * @var MockObject | LoginPageBehaviour
	 */
	private $loginPageBehaviour;
	/**
	 * @var MockObject | IUserSession
	 */
	private $userSession;
	/**
	 * @var MockObject | IURLGenerator
	 */
	private $urlGenerator;
	/**
	 * @var MockObject | IRequest
	 */
	private $request;

	protected function setUp(): void {
		parent::setUp();
		$this->logger = $this->createMock(Logger::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->urlGenerator = $this->createMock(IURLGenerator::class);
		$this->request = $this->createMock(IRequest::class);

		$this->loginPageBehaviour = $this->getMockBuilder(LoginPageBehaviour::class)
			->setConstructorArgs([$this->logger, $this->userSession, $this->urlGenerator, $this->request])
			->setMethods(['registerAlternativeLogin', 'redirect'])
			->getMock();
	}

	public function testLoggedIn(): void {
		$this->userSession->method('isLoggedIn')->willReturn(true);
		$this->loginPageBehaviour->expects(self::never())->method('registerAlternativeLogin');
		$this->loginPageBehaviour->handleLoginPageBehaviour([]);
	}

	public function testNotLoggedInNoAutoRedirect(): void {
		$this->userSession->method('isLoggedIn')->willReturn(false);
		$this->request->expects(self::never())->method('getRequestUri');
		$this->loginPageBehaviour->expects(self::once())->method('registerAlternativeLogin')->with('foo');
		$this->loginPageBehaviour->handleLoginPageBehaviour(['loginButtonName' => 'foo']);
	}

	public function testNotLoggedInAutoRedirect(): void {
		$this->userSession->method('isLoggedIn')->willReturn(false);
		$this->request->method('getRequestUri')->willReturn('https://example.com/login');
		$this->urlGenerator->method('linkToRoute')->willReturn('https://example.com/openid/redirect');
		$this->loginPageBehaviour->expects(self::once())->method('registerAlternativeLogin')->with('OpenID Connect');
		$this->loginPageBehaviour->expects(self::once())->method('redirect')->with('https://example.com/openid/redirect');
		$this->loginPageBehaviour->handleLoginPageBehaviour(['autoRedirectOnLoginPage' => true]);
	}

	public function testNotLoggedInAutoRedirectNoLoginPage(): void {
		$this->userSession->method('isLoggedIn')->willReturn(false);
		$this->request->method('getRequestUri')->willReturn('https://example.com/apps/files');
		$this->urlGenerator->method('linkToRoute')->willReturn('https://example.com/openid/redirect');
		$this->loginPageBehaviour->expects(self::once())->method('registerAlternativeLogin')->with('OpenID Connect');
		$this->loginPageBehaviour->expects(self::never())->method('redirect')->with('https://example.com/openid/redirect');
		$this->loginPageBehaviour->handleLoginPageBehaviour(['autoRedirectOnLoginPage' => true]);
	}
}
