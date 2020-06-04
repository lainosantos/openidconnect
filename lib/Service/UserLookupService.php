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
namespace OCA\OpenIdConnect\Service;

use OC\HintException;
use OC\User\LoginException;
use OCA\OpenIdConnect\Client;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IConfig;
use OCP\ILogger;
use OCP\Mail\IMailer;
use OCP\Security\ISecureRandom;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
use OCA\OpenIdConnect\Logger;
use OCP\Util;

class UserLookupService {

	/**
	 * @var IUserManager
	 */
	private $userManager;
	/**
	 * @var Client
	 */
	private $client;
    /**
     * @var IL10N
     */
    private $l10n;
    /**
     * @var IConfig
     */
	private $config;
    /**
     * @var ILogger
     */
    private $logger;
    /**
     * @var \OC_Defaults
     */
    private $defaults;
    /**
     * @var IMailer
     */
    private $mailer;
    /**
     * @var IURLGenerator
     */
    private $urlGenerator;
    /**
     * @var ISecureRandom
     */
    private $secureRandom;
    /**
     * @var ITimeFactory
     */
    protected $timeFactory;
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

	public function __construct(IUserManager $userManager,
								Client $client,
                                IL10N $l10n,
                                IConfig $config,
                                ISecureRandom $secureRandom,
                                ILogger $logger,
                                \OC_Defaults $defaults,
                                IMailer $mailer,
                                ITimeFactory $timeFactory,
                                IURLGenerator $urlGenerator,
                                EventDispatcherInterface $eventDispatcher) {
		$this->userManager = $userManager;
		$this->client = $client;
        $this->l10n = $l10n;
		$this->config = $config;
        $this->secureRandom = $secureRandom;
        $this->logger = new Logger($logger);
        $this->defaults = $defaults;
        $this->mailer = $mailer;
        $this->timeFactory = $timeFactory;
        $this->urlGenerator = $urlGenerator;
		$this->eventDispatcher = $eventDispatcher;
	}

	/**
	 * @param mixed $userInfo
	 * @return IUser
	 * @throws LoginException
	 * @throws HintException
	 */
	public function lookupUser($userInfo): IUser {
		$openIdConfig = $this->client->getOpenIdConfig();
		if ($openIdConfig === null) {
			throw new HintException('Configuration issue in openidconnect app');
		}
		$searchByEmail = true;
		if (isset($openIdConfig['mode']) && $openIdConfig['mode'] === 'userid') {
			$searchByEmail = false;
		}
		$attribute = $openIdConfig['search-attribute'] ?? 'email';

		if ($searchByEmail) {
			$usersByEmail = $this->userManager->getByEmail($userInfo->$attribute);
			if (\count($usersByEmail) > 1) {
				throw new LoginException("{$userInfo->$attribute} is not unique.");
			}
            $user = $usersByEmail ? $usersByEmail[0] : null;
		} else {
            $user = $this->userManager->get($userInfo->$attribute);
        }

        $enableImport = $openIdConfig['import']['enabled'] ?? false;
		if (!$user && $enableImport) {
            $uid = $userInfo->{$openIdConfig['import']['uid-attribute']};
		    $email = $userInfo->{$openIdConfig['import']['email-attribute']};
		    $displayName = $userInfo->{$openIdConfig['import']['display-name-attribute']};

		    if (!$this->mailer->validateMailAddress($email)) {
                throw new LoginException('Invalid mail address.');
            }

            $event = new GenericEvent();
            $this->eventDispatcher->dispatch($event, 'OCP\User::createPassword');
            if ($event->hasArgument('password')) {
                $password = $event->getArgument('password');
            } else {
                $password = $this->secureRandom->generate(20);
            }

            try {
                $user = $this->userManager->createUser($uid, $password);
            } catch (\Exception $e) {
                $this->logger->error("Can't create new user: " . $e->getMessage());
                throw new LoginException("Can't import new user from openid provider.");
            }

            if ($user) {
                $user->setEMailAddress($email);
                $user->setDisplayName($displayName);

                try {
                    $this->generateTokenAndSendMail($uid, $email);
                } catch (\Exception $e) {
                    $this->logger->error("Can't send new user mail to $email: " . $e->getMessage(), ['app' => 'settings']);
                }
            } else {
                $this->logger->error("Can't import new user from openid provider.");
            }
        }

		if (!$user) {
			throw new LoginException("User {$userInfo->$attribute} is not known.");
		}
		return $user;
	}

    /**
     * @param string $userId
     * @param string $email
     */
    private function generateTokenAndSendMail($userId, $email) {
        $token = $this->secureRandom->generate(21,
            ISecureRandom::CHAR_DIGITS,
            ISecureRandom::CHAR_LOWER, ISecureRandom::CHAR_UPPER);
        $this->config->setUserValue($userId, 'owncloud',
            'lostpassword', $this->timeFactory->getTime() . ':' . $token);

        // data for the mail template
        $mailData = [
            'username' => $userId,
            'url' => $this->urlGenerator->linkToRouteAbsolute('settings.Users.setPasswordForm', ['userId' => $userId, 'token' => $token])
        ];

        $mail = new TemplateResponse('settings', 'email.new_user', $mailData, 'blank');
        $mailContent = $mail->render();

        $mail = new TemplateResponse('settings', 'email.new_user_plain_text', $mailData, 'blank');
        $plainTextMailContent = $mail->render();

        $subject = $this->l10n->t('Your %s account was created', [$this->defaults->getName()]);

        $message = $this->mailer->createMessage();
        $message->setTo([$email => $userId]);
        $message->setSubject($subject);
        $message->setHtmlBody($mailContent);
        $message->setPlainBody($plainTextMailContent);
        $message->setFrom([Util::getDefaultEmailAddress('no-reply') => $this->defaults->getName()]);
        $this->mailer->send($message);
    }
}
