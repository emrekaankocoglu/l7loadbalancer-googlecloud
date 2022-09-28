#!/bin/bash -xe

sleep 10

apt-get update
apt-get install -y apache2 libapache2-mod-php

cat > /var/www/html/index.php <<'EOF'
<?php
function metadata_value($value) {
    $opts = array(
        "http" => array(
            "method" => "GET",
            "header" => "Metadata-Flavor: Google"
        )
    );
    $context = stream_context_create($opts);
    $content = file_get_contents("http://metadata/computeMetadata/v1/$value", false, $context);
    return $content;
}
if ($_SERVER['HTTP_X_FORWARDED_PROTO'] == "http") {
		$redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
		header('HTTP/1.1 301 Moved Permanently');
		header('Location: ' . $redirect);
		exit();
}
?>

<!doctype html>
<html>
<body>
	<p>
	Instance that served this page: <?php printf(metadata_value("instance/name")) ?>
	Layer 7 Load Balancer (Proxy) IP: <?php printf($_SERVER["HTTP_HOST"]); ?>
	</p>
</body>
</html>
EOF

mv /var/www/html/index.html /var/www/html/index.html.old || echo "Old index doesn't exist"

[[ -n "${PROXY_PATH}" ]] && mkdir -p /var/www/html/${PROXY_PATH} && cp /var/www/html/index.php /var/www/html/${PROXY_PATH}/index.php

chkconfig httpd on || systemctl enable httpd || systemctl enable apache2
service httpd restart || systemctl restart httpd || systemctl restart apache2
