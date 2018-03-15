<?php

namespace Grav\Plugin;

use Assert\Assertion;
use Assert\AssertionFailedException;
use Grav\Common\Page\Page;
use Grav\Common\Plugin;
use Grav\Common\Session;
use Grav\Common\Uri;
use Grav\Common\User\User;
use Grav\Plugin\KeycloakSSO\Controller;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use RocketTheme\Toolbox\Event\Event;

/**
 * Class KeycloakSSOPlugin
 * @package Grav\Plugin
 */
class KeycloakSSOPlugin extends Plugin
{
    /**
     * @return array
     *
     * The getSubscribedEvents() gives the core a list of events
     *     that the plugin wants to listen to. The key of each
     *     array section is the event that the plugin listens to
     *     and the value (in the form of an array) contains the
     *     callable (or function) as well as the priority. The
     *     higher the number the higher the priority.
     */
    public static function getSubscribedEvents()
    {
        return [
            'onPluginsInitialized' => ['onPluginsInitialized', 0],
            'onPageInitialized' => ['onPageInitialized', 0]
        ];
    }

    /**
     * Initialize the plugin
     * @throws OpenIDConnectClientException
     */
    public function onPluginsInitialized()
    {
        // Check to ensure login plugin is enabled.
        if (!$this->grav['config']->get('plugins.login.enabled')) {
            throw new \RuntimeException('The Login plugin needs to be installed and enabled');
        }

        if ($this->grav['config']->get('system.session.split')) {
            throw new \RuntimeException('Session splitting must be disabled');
        }

        if ($this->grav['user']->authorize('site.login')) {
            return;
        } else {
            require_once __DIR__ . '/vendor/autoload.php';

            $server = $this->grav['config']->get('plugins.keycloak-sso.server');
            $client = $this->grav['config']->get('plugins.keycloak-sso.client_id');
            $secret = $this->grav['config']->get('plugins.keycloak-sso.client_secret');
            $editors = $this->grav['config']->get('plugins.keycloak-sso.editors') ?? [];

            /** @var Uri $uri */
            $uri = $this->grav['uri'];

            try {
                Assertion::notBlank($server);
                Assertion::notBlank($client);
                Assertion::notBlank($secret);
            } catch (AssertionFailedException $e) {
                if ($this->isAdmin()) {
                    return;
                } else {
                    $this->grav->redirect('/admin');
                }
            }

            $oidc   = new OpenIDConnectClient($server, $client, $secret);
            $oidc->setRedirectURL($uri->base() . '/oidc_login');
            $oidc->authenticate();

            $userinfo = (array) $oidc->requestUserInfo();
            $user = User::load($userinfo['preferred_username']);
            if (!$user->exists()) {
                $user->set('state', 'enabled');
                $user->set('email', $userinfo['email']);
                $user->set('fullname', $userinfo['name']);
                $user->set('username', $userinfo['preferred_username']);
                $user->set('authenticated', true);
                $user->set('access.site.login', true);
                if (in_array($userinfo['preferred_username'], $editors)) {
                    $user->set('access.admin.login', true);
                    $user->set('access.admin.super', true);
                }
                $user->save();
            }

            $this->grav['session']->user = $user;
            unset($this->grav['user']);
            $this->grav['user'] = $user;
        }
    }

    public function onPageInitialized()
    {
        $uri = $this->grav['uri'];
        if ($uri->path() == '/oidc_login') {
            $this->grav->redirect('/', 302);
        }
    }
}
