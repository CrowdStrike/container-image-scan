FROM nginx:latest
COPY scripts/gen_hostname.sh /docker-entrypoint.d/99-gen_hostname.sh 
RUN rm /usr/share/nginx/html/index.html && chmod 774 /docker-entrypoint.d/99-gen_hostname.sh
EXPOSE 80