import unittest

from scanner.cameras.classify import classify_camera, guess_admin_url, guess_rtsp_url
from scanner.nvr.classify import classify_nvr


class TestCameraClassification(unittest.TestCase):
    def test_rtsp_port_is_camera_signal(self):
        open_ports = [{"port": 554, "service": "RTSP"}]
        is_camera, reasons = classify_camera(open_ports, {}, None)
        self.assertTrue(is_camera)
        self.assertTrue(reasons)

    def test_onvif_is_camera_signal(self):
        onvif_info = {"xaddrs": ["http://192.168.1.50/onvif/device_service"], "types": "NetworkVideoTransmitter"}
        is_camera, reasons = classify_camera([], {}, onvif_info)
        self.assertTrue(is_camera)
        self.assertIn("ONVIF", reasons[0])

    def test_banner_keyword_is_camera_signal(self):
        banners = {80: {"server": "Boa/0.94.14rc21", "title": "NETWORK CAMERA"}}
        is_camera, reasons = classify_camera([{"port": 80, "service": "HTTP"}], banners, None)
        self.assertTrue(is_camera)

    def test_plain_host_is_not_camera(self):
        open_ports = [{"port": 22, "service": "SSH"}]
        is_camera, reasons = classify_camera(open_ports, {}, None)
        self.assertFalse(is_camera)
        self.assertEqual(reasons, [])

    def test_rtsp_url_guess(self):
        self.assertEqual(guess_rtsp_url("10.0.0.5", [{"port": 554, "service": "RTSP"}]), "rtsp://10.0.0.5:554/")
        self.assertIsNone(guess_rtsp_url("10.0.0.5", [{"port": 80, "service": "HTTP"}]))

    def test_admin_url_prefers_http_first_match(self):
        ports = [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]
        self.assertEqual(guess_admin_url("10.0.0.5", ports), "http://10.0.0.5:80/")


class TestNvrClassification(unittest.TestCase):
    def test_nvr_keyword_in_title(self):
        banners = {80: {"server": None, "title": "NVR Login"}}
        is_nvr, reasons, subtype = classify_nvr(banners)
        self.assertTrue(is_nvr)
        self.assertTrue(reasons)
        self.assertEqual(subtype, "NVR")

    def test_dvr_keyword_in_server_header(self):
        banners = {80: {"server": "Embedded DVR WebServer", "title": None}}
        is_nvr, _, subtype = classify_nvr(banners)
        self.assertTrue(is_nvr)
        self.assertEqual(subtype, "DVR")

    def test_camera_banner_is_not_nvr(self):
        banners = {80: {"server": "Boa/0.94.14rc21", "title": "NETWORK CAMERA"}}
        is_nvr, reasons, subtype = classify_nvr(banners)
        self.assertFalse(is_nvr)
        self.assertEqual(reasons, [])
        self.assertIsNone(subtype)

    def test_camera_and_nvr_are_mutually_distinguishable(self):
        """Un dispositivo con RTSP ma banner "camera" e' una camera, non un NVR:
        la distinzione finale sta a scan_engine, ma i due classificatori
        devono restare indipendenti l'uno dall'altro."""
        open_ports = [{"port": 554, "service": "RTSP"}]
        banners = {80: {"server": None, "title": "IP CAMERA"}}
        is_camera, _ = classify_camera(open_ports, banners, None)
        is_nvr, _, _ = classify_nvr(banners)
        self.assertTrue(is_camera)
        self.assertFalse(is_nvr)

    def test_xvr_keyword_classified_as_dvr(self):
        """Le Dahua XVR (registratori ibridi analogico+IP) vanno trattate
        come DVR: al fine di questo tool (e' un registratore) la
        distinzione XVR/DVR non e' rilevante."""
        banners = {80: {"server": "Dahua XVR5108HS", "title": None}}
        is_nvr, _, subtype = classify_nvr(banners)
        self.assertTrue(is_nvr)
        self.assertEqual(subtype, "DVR")

    def test_encoder_keyword_classified_separately_from_nvr(self):
        banners = {80: {"server": None, "title": "Video Encoder Configuration"}}
        is_nvr, _, subtype = classify_nvr(banners)
        self.assertTrue(is_nvr)
        self.assertEqual(subtype, "Video Encoder")

    def test_generic_recorder_keyword_falls_back_to_umbrella_label(self):
        """"recorder"/"video recorder" da soli non permettono di scegliere
        tra NVR e DVR: resta l'etichetta generica, non un tipo specifico
        inventato senza un segnale che lo indichi davvero."""
        banners = {80: {"server": None, "title": "Recorder Web Interface"}}
        is_nvr, _, subtype = classify_nvr(banners)
        self.assertTrue(is_nvr)
        self.assertEqual(subtype, "NVR/DVR")


if __name__ == "__main__":
    unittest.main()
