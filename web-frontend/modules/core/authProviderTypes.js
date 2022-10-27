import { Registerable } from '@baserow/modules/core/registry'

/**
 * The authorization provider type base class that can be extended when creating
 * a plugin for the frontend.
 */
export class AuthProviderType extends Registerable {
  /**
   * The font awesome 5 icon name that is used as convenience for the user to
   * recognize certain application types. If you for example want the database
   * icon, you must return 'database' here. This will result in the classname
   * 'fas fa-database'.
   */
  getIconClass() {
    return null
  }

  /**
   * A human readable name of the application type.
   */
  getName() {
    return null
  }

  /**
   * A human readable name of the application type.
   */
  getProviderName(provider) {
    return null
  }

  /**
   * The component that will be rendered in the SSO admin section
   * where all the providers are listed.
   */
  getAdminListComponent() {
    return null
  }

  /**
   * The sidebar component will be rendered in the sidebar if the application is
   * in the selected group. All the applications of a group are listed in the
   * sidebar and this component should give the user the possibility to select
   * that application.
   */
  getAdminSettingsComponent() {
    return null
  }

  /**
   * The login link are shown in the login page above the username and
   * password form. This is the place where OAuth2 buttons can be added.
   */
  getLoginButtonComponent() {
    return null
  }

  /**
   * The login actions are shown in the login page below the username and
   * password form. This is the place where SAML or openID link/button can be
   * added.
   */
  getLoginActionComponent() {
    return null
  }

  populateLoginOptions(authProviderOption) {
    return {
      hasLoginButton: this.getLoginButtonComponent() !== null,
      hasLoginAction: this.getLoginActionComponent() !== null,
      ...authProviderOption,
    }
  }

  populate(authProviderType) {
    return {
      type: this.getType(),
      order: this.getOrder(),
      hasAdminSettings: this.getAdminListComponent() !== null,
      canCreateNewProviders: authProviderType.can_create_new,
      authProviders: authProviderType.auth_providers,
    }
  }

  constructor(...args) {
    super(...args)
    this.type = this.getType()
    this.iconClass = this.getIconClass()

    if (this.type === null) {
      throw new Error('The type name of an application type must be set.')
    }
    if (this.iconClass === null) {
      throw new Error('The icon class of an application type must be set.')
    }
    if (this.name === null) {
      throw new Error('The name of an application type must be set.')
    }
  }

  /**
   * @return object
   */
  serialize() {
    return {
      type: this.type,
      iconClass: this.iconClass,
      name: this.getName(),
      routeName: this.routeName,
    }
  }

  getOrder() {
    throw new Error('The order of an application type must be set.')
  }
}

export class PasswordAuthProviderType extends AuthProviderType {
  getType() {
    return 'password'
  }

  getIconClass() {
    return 'key'
  }

  getName() {
    return 'Password'
  }

  getProviderName(provider) {
    return null
  }

  getOrder() {
    return 100
  }
}
