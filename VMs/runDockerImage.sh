#docker run -t -i -p 8443:8443 --rm benchmark /bin/bash -c "git pull && ./runRemoteAccessibleBenchmark.sh"
#docker run -t -i -p 8443:8443 --rm benchmark /bin/bash # -v ../results/:/owasp/BenchmarkJava/results/ -v ../scorecard/:/owasp/BenchmarkJava/scorecard/ # -c "git pull && ./runRemoteAccessibleBenchmark.sh"
#docker run -t -i -p 8443:8443 --rm benchmark --volume ../results/:/owasp/BenchmarkJava/results/ --volume ../scorecard/:/owasp/BenchmarkJava/scorecard/ /bin/bash # -c "git pull && ./runRemoteAccessibleBenchmark.sh"
docker run -t -i -p 8443:8443 --rm \
--volume /home/greggor/MAG/BenchmarkJava/results:/owasp/BenchmarkJava/results/ \
--volume /home/greggor/MAG/BenchmarkJava/scorecard:/owasp/BenchmarkJava/scorecard/ \
benchmark /bin/bash -c "./createScorecards.sh"
# benchmark /bin/bash -c "codeql"
#benchmark /bin/bash -c "../../Tools/codeql-home/codeql/codeql database create owasp-benchmark --language=java"



# /owasp/BenchmarkUtils/plugin/src/main/java/org/owasp/benchmarkutils/score/parsers
