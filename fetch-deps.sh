mkdir -p lib/
set -e
git clone https://github.com/spicy-lime/jediterm ext/
pushd ext
gradle distZip
gradle sourceJar :core:sourcesJar
gradle sourceJar :ui:sourcesJar
mv ./.gradleBuild/JediTerm/distributions/JediTerm-3.51-SNAPSHOT.zip .
unzip JediTerm-3.51-SNAPSHOT.zip
mv ./.gradleBuild/ui/libs/jediterm-ui-3.51-SNAPSHOT-sources.jar JediTerm-3.51-SNAPSHOT/lib/
mv ./.gradleBuild/core/libs/jediterm-core-3.51-SNAPSHOT-sources.jar JediTerm-3.51-SNAPSHOT/lib/
mkdir unpacked
pushd unpacked
for f in ../JediTerm-3.51-SNAPSHOT/lib/*.jar; do
  jar xf "$f"
done
jar cf ../../jediterm.jar *
popd
popd
mv jediterm.jar lib/
rm -rf ext
