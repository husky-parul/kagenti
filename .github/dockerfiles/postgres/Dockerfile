FROM postgres:18.3@sha256:69e8582b781cb44fa4557b98ed586fe68361e320d9b12f9707494335634f4f3d
RUN mkdir temp
RUN groupadd non-root-postgres-group
RUN useradd non-root-postgres-user --group non-root-postgres-group
RUN chown -R non-root-postgres-user:non-root-postgres-group /temp
RUN chmod 777 /temp
USER non-root-postgres