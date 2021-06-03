cat <<EOF > /usr/share/nginx/html/index.html
<body>
<p><h2>NGINX IS RUNNING!</h2></b></p>
<p>The container hostname is: $(hostname)</p>
</body>
</html>
EOF