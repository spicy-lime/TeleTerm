pushd unpacked
for f in ../lib/*.jar; do
  jar xf "$f"
done
popd

