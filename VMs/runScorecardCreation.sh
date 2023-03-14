docker run -t -i -p 8443:8443 --rm \
--volume /home/greggor/MAG/BenchmarkJava/results:/owasp/BenchmarkJava/results/ \
--volume /home/greggor/MAG/BenchmarkJava/scorecard:/owasp/BenchmarkJava/scorecard/ \
benchmark /bin/bash -c "./createScorecards.sh"
