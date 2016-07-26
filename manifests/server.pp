#
class openldap::server (
  $root_dn,
  $root_password,
  $suffix,
  $access                    = [
    'to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage', # lint:ignore:80chars
  ],
  $accesslog                 = false,
  $accesslog_cachesize       = undef,
  $accesslog_checkpoint      = undef,
  $accesslog_db_config       = [],
  $accesslog_dn_cachesize    = undef,
  $accesslog_index_cachesize = undef,
  $args_file                 = $::openldap::params::args_file,
  $auditlog                  = false,
  $auditlog_file             = $::openldap::params::auditlog_file,
  $backend_modules           = $::openldap::params::backend_modules,
  $data_cachesize            = undef,
  $data_checkpoint           = undef,
  $data_db_config            = [],
  $data_directory            = $::openldap::params::data_directory,
  $data_dn_cachesize         = undef,
  $data_index_cachesize      = undef,
  $db_backend                = $::openldap::params::db_backend,
  $group                     = $::openldap::params::group,
  $indices                   = [],
  $ldap_interfaces           = $::openldap::params::ldap_interfaces,
  $ldaps_interfaces          = $::openldap::params::ldaps_interfaces,
  $limits                    = [],
  $local_ssf                 = undef,
  $log_level                 = $::openldap::params::log_level,
  $module_extension          = $::openldap::params::module_extension,
  $package_name              = $::openldap::params::server_package_name,
  $pid_file                  = $::openldap::params::pid_file,
  $ppolicy                   = false,
  $pp_hash_cleartext         = undef,
  $pp_use_lockout            = undef,
  $pp_forward_updates        = undef,
  $pwd_attr                  = undef,
  $pwd_min_age               = undef,
  $pwd_max_age               = undef,
  $pwd_in_history            = undef,
  $pwd_check_quality         = undef,
  $pwd_min_length            = undef,
  $pwd_expire_warning        = undef,
  $pwd_grace_auth_nlimit     = undef,
  $pwd_lockout               = undef,
  $pwd_lockout_duration      = undef,
  $pwd_max_failure           = undef,
  $pwd_fail_count_interval   = undef,
  $pwd_must_change           = undef,
  $pwd_allow_user_change     = undef,
  $pwd_safe_modify           = undef,
  $pwd_max_total_attempts    = undef,
  $pwd_check_module          = undef,
  $replica_dn                = undef,
  $schema_dir                = $::openldap::params::schema_dir,
  $security                  = undef,
  $size_limit                = undef,
  $smbk5pwd                  = false,
  $smbk5pwd_backends         = [],
  $smbk5pwd_must_change      = undef,
  $ssl_ca                    = $::openldap::params::ssl_ca,
  $ssl_cert                  = $::openldap::params::ssl_cert,
  $ssl_certs_dir             = $::openldap::params::ssl_certs_dir,
  $ssl_cipher                = $::openldap::params::ssl_cipher,
  $ssl_dhparam               = $::openldap::params::ssl_dhparam,
  $ssl_key                   = $::openldap::params::ssl_key,
  $ssl_protocol              = $::openldap::params::ssl_protocol,
  $syncprov                  = false,
  $syncprov_checkpoint       = $::openldap::params::syncprov_checkpoint,
  $syncprov_sessionlog       = $::openldap::params::syncprov_sessionlog,
  $syncrepl                  = undef,
  $time_limit                = undef,
  $update_ref                = undef,
  $user                      = $::openldap::params::user,
) inherits ::openldap::params {

  if ! defined(Class['::openldap::client']) {
    fail('You must include the openldap::client class before using the openldap::server class') # lint:ignore:80chars
  }

  validate_string($root_dn)
  validate_string($root_password)
  validate_string($suffix)

  validate_array($access)
  validate_bool($accesslog)
  if $accesslog_cachesize {
    validate_integer($accesslog_cachesize)
  }
  if $accesslog_checkpoint {
    validate_re($accesslog_checkpoint, '^\d+\s+\d+$')
  }
  validate_array($accesslog_db_config)
  if $accesslog_dn_cachesize {
    validate_integer($accesslog_dn_cachesize)
  }
  if $accesslog_index_cachesize {
    validate_integer($accesslog_index_cachesize)
  }
  validate_bool($auditlog)
  if $auditlog {
    validate_absolute_path($auditlog_file)
  }
  validate_absolute_path($args_file)
  validate_array($backend_modules)
  if $data_cachesize {
    validate_integer($data_cachesize)
  }
  if $data_checkpoint {
    validate_re($data_checkpoint, '^\d+\s+\d+$')
  }
  validate_array($data_db_config)
  validate_absolute_path($data_directory)
  if $data_dn_cachesize {
    validate_integer($data_dn_cachesize)
  }
  if $data_index_cachesize {
    validate_integer($data_index_cachesize)
  }
  validate_string($db_backend)
  validate_string($group)
  validate_array($indices)
  validate_array($ldap_interfaces)
  validate_array($ldaps_interfaces)
  if $limits {
    validate_array($limits)
  }
  if $local_ssf {
    validate_integer($local_ssf)
  }
  if $log_level {
    validate_re($log_level, '^(?:\d+|0x\h+|\w+)(?:\s+(?:\d+|0x\h+|\w+))*$')
  }
  validate_string($package_name)
  validate_absolute_path($pid_file)
  if $ppolicy {
    validate_re($pp_hash_cleartext, '^TRUE$|^FALSE$')
    validate_re($pp_use_lockout, '^TRUE$|^FALSE$')
    validate_re($pp_forward_updates, '^TRUE$|^FALSE$')
    validate_string($pwd_attr)
  }
  if $pwd_min_age {
    validate_re($pwd_min_age, '\d+$')
  }
  if $pwd_max_age {
    validate_re($pwd_max_age, '\d+$')
  }
  if $pwd_in_history {
    validate_re($pwd_max_age, '\d+$')
  }
  if $pwd_check_quality {
    validate_re($pwd_check_quality, '0|1|2')
    if $pwd_check_quality == '1' or $pwd_check_quality == '2' {
      validate_string($pwd_check_module)
      $use_ppolicy_checker = true
    }
  }
  if $pwd_min_length  {
    validate_re($pwd_min_length, '\d+$')
  }
  if $pwd_expire_warning {
    validate_re($pwd_min_length, '\d+$')
  }
  if $pwd_grace_auth_nlimit {
    validate_re($pwd_grace_auth_nlimit, '\d+$') 
  }
  if $pwd_lockout {
    validate_re($pwd_lockout, '^TRUE$|^FALSE$')
  }
  if $pwd_lockout_duration {
    validate_re($pwd_lockout_duration, '\d+$')
  }
  if $pwd_max_failure {
    validate_re($pwd_max_failure, '\d+$')
  }
  if $pwd_fail_count_interval {
    validate_re($pwd_fail_count_interval, '\d+$')
  }
  if $pwd_must_change {
    validate_re($pwd_must_change, '^TRUE$|^FALSE$')
  }
  if $pwd_allow_user_change {
    validate_re($pwd_allow_user_change, '^TRUE$|^FALSE$')
  }
  if $pwd_safe_modify {
    validate_re($pwd_safe_modify, '^TRUE$|^FALSE$')
  }
  if $pwd_max_total_attempts {
    validate_re($pwd_max_total_attempts, '\d+$')
  }
  validate_absolute_path($schema_dir)
  if $security {
    validate_re($security, '^\w+=\d+(?:\s+\w+=\d+)*$')
  }
  if $size_limit {
    validate_re("${size_limit}", '^(?:(size)(?:\.\w+)?=)?(?:\d+|unlimited)(?:\s+\1(?:\.\w+)?=(?:\d+|unlimited))*$') # lint:ignore:80chars lint:ignore:only_variable_string
  }
  validate_bool($smbk5pwd)
  if $smbk5pwd {
    validate_array($smbk5pwd_backends)
    if $smbk5pwd_must_change {
      validate_integer($smbk5pwd_must_change)
    }
  }
  if $ssl_ca {
    validate_absolute_path($ssl_ca)
  }
  if $ssl_cert {
    validate_absolute_path($ssl_cert)
  }
  if $ssl_certs_dir {
    validate_absolute_path($ssl_certs_dir)
  }
  if $ssl_cipher {
    validate_string($ssl_cipher)
  }
  if $ssl_dhparam {
    validate_absolute_path($ssl_dhparam)
  }
  if $ssl_key {
    validate_absolute_path($ssl_key)
  }
  if $ssl_protocol {
    validate_number($ssl_protocol)
  }
  validate_bool($syncprov)
  if $syncprov {
    validate_string($replica_dn)
    validate_re($syncprov_checkpoint, '^\d+\s+\d+$')
    validate_integer($syncprov_sessionlog)
  }
  if $syncrepl {
    validate_array($syncrepl)
  }
  if $time_limit {
    validate_re("${time_limit}", '^(?:(time)(?:\.\w+)?=)?(?:\d+|unlimited)(?:\s+\1(?:\.\w+)?=(?:\d+|unlimited))*$') # lint:ignore:80chars lint:ignore:only_variable_string
  }
  if $update_ref {
    validate_array($update_ref)
  }
  validate_string($user)

  include ::openldap::server::install
  include ::openldap::server::config
  include ::openldap::server::service

  anchor { 'openldap::server::begin': }
  anchor { 'openldap::server::end': }

  Anchor['openldap::server::begin'] -> Class['::openldap::server::install']
    -> Class['::openldap::server::service'] -> Anchor['openldap::server::end']

  Class['::openldap::server::install'] -> Class['::openldap::server::config']
    -> Anchor['openldap::server::end']
}
