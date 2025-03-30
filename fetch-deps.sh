set -e
git clone https://github.com/spicy-lime/jediterm ext/
pushd ext
gradle distZip
mv ./.gradleBuild/JediTerm/distributions/JediTerm-3.51-SNAPSHOT.zip .
unzip JediTerm-3.51-SNAPSHOT.zip
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
