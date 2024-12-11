<html>
<head>
<style>
</style>
</head>

<?php 
$this_page = $_SERVER['PHP_SELF'].'?page='.$_GET['page'];

if ($_POST['process']=='update') 
{
    update_option('jbxl_auth_server_fqdn', $_POST['server_fqdn']);
	update_option('jbxl_auth_server_port', $_POST['server_port']);
}

//
$jbxl_auth_server_fqdn = get_option('jbxl_auth_server_fqdn');
$jbxl_auth_server_port = get_option('jbxl_auth_server_port');
?>


<body>
<div class="container">
<div class="banner"><h1>JBXL Auth Plugin v1.0</h1></div>

<form style="display::inline;" method="post" action="<?php echo str_replace( '%7E', '~', $_SERVER['REQUEST_URI']); ?>&updated=true">
<h2>Settings</h2>
<p>
<strong>JBXL Auth Server FQDN or IP </strong>&nbsp;
<input name="server_fqdn" type="text" value="<?php  echo $jbxl_auth_server_fqdn; ?>" size="30" /><br />
<strong>JBXL Auth Server Port Number</strong>&nbsp;
<input name="server_port" type="text" value="<?php  echo $jbxl_auth_server_port; ?>" size="6"  /><br />
</p>
<input type="hidden" name="process" value="update" />
<input type="submit" name="button_submit" value="<?php _e('Update Options', 'jbxl_auth') ?> &raquo;" />

</div>
</div>
</body>
</html>
