# Detector dependencies

The artifact does not vendor third-party detector repositories. To prepare the
source dependencies, run:

```bash
./third_party/setup_detectors.sh
```

The script clones the pinned upstream revisions into the artifact root and
applies the small local overlays in `third_party/patches/`.

| Detector | Upstream revision | Overlay |
|---|---|---|
| OpenVul | `b2769f7916a533a69ce4fd14588fcf6c6a83a18b` | `openvul.patch` |
| VulnLLM-R | `5357371a2271df1048666220415a3bc937af5f9d` | `vulnllmr.patch` |
| Vul-RAG | `38aa707fdb6bf592f1ed7753e90af400d3b9dcd3` | none |
| VulTrial | `d5ed8e0735004060b55173c38450f4adf2612cb2` | `vultrial.patch` |
