esp32-hsslms
=============

This is an implementation of Leighton-Micali Hash-Based Signatures for an ESP32
according to `RFC 8554 <https://www.rfc-editor.org/rfc/rfc8554.html>`_ using the Arduino-IDE.

The implementation is based on the source code of `cpp-hsslms<https://github.com/pmvr/cpp-hsslms>`_ and is meant as a reference and for educational purposes.

The implementation provides 3 classes:

* LM-OTS One-Time Signatures. These are one-time signatures; each private key MUST be used at most one time to sign a message.
* Leighton-Micali Signatures (LMS). This systemholds a fixed number of one-time signatures, i.e. LM-OTS.
* Hierarchical Signatures (HSS). This system uses a sequence of LMS.


Performance Measurements of HSS
-------------------------------

The measurements are done on an ESP32. Because of limited resources Merkle trees of height 5 only can be computed.

Key Generationo of H5
^^^^^^^^^^^^^^^^^^^^^

+----------+-----+-----+-----+-----+
| Key-Type | Time[s]               |
+==========+=====+=====+=====+=====+
| w        | 1   | 2   | 4   | 8   |
+----------+-----+-----+-----+-----+
| H5       | n/a | 0.5 | 1.0 | 8.3 |
+----------+-----+-----+-----+-----+


Performance of Signature Generation:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+----------+-----+-----+-----+-----+
| Key-Type | Time[ms]               |
+==========+=====+=====+=====+=====+
| w        | 1   | 2   | 4   | 8   |
+----------+-----+-----+-----+-----+
| H5       | n/a | 9   | 18  | 131 |
+----------+-----+-----+-----+-----+

Performance of Signature Verification:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+----------+-----+-----+-----+-----+
| Key-Type | Time[ms]               |
+==========+=====+=====+=====+=====+
| w        | 1   | 2   | 4   | 8   |
+----------+-----+-----+-----+-----+
| H5       | n/a | 9   | 16  | 132 |
+----------+-----+-----+-----+-----+

License
=======

`MIT <https://opensource.org/licenses/MIT>`__
