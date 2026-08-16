<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
delete_option( 'passkey_first_settings' );
delete_metadata( 'user', 0, '_pf_required_since', '', true );
