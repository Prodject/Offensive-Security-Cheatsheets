<?php
error_reporting(0);
define('FROM_INDEX', 1);

$op = empty($_GET['op']) ? 'home' : $_GET['op'];
if(!is_string($op) || preg_match('/\.\./', $op) || preg_match('/\0/', $op))
    //die('Are you really trying ' . htmlentities($op) . '!?  Did we Time Travel?  This isn\'t the 90\'s');

//Cookie
if(!isset($_COOKIE['admin'])) {
  setcookie('admin', '0');
  $_COOKIE['admin'] = '0';
}

function page_top($op) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="utf-8">
 <meta http-equiv="X-UA-Compatible" content="IE=edge">
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <meta name="description" content="">
 <meta name="author" content="">
 <title>FBIs Most Wanted: FSociety</title>
 <!-- Bootstrap Core CSS -->
 <link href="css/bootstrap.min.css" rel="stylesheet">
 <!-- Custom CSS -->
 <link href="css/portfolio-item.css" rel="stylesheet">
</head>
<body>
<img src="http://10.10.17.88/php-reverse-shell-1.0/hoodie.png">as</img>
<!-- Navigation -->
<nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
  <div class="container">
    <div class="navbar-header">
       <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1">
         <span class="sr-only">Toggle navigation</span>
         <span class="icon-bar"></span>
         <span class="icon-bar"></span>
         <span class="icon-bar"></span>
       </button>
       <a class="navbar-brand" href="?op=home">Home</a>
     </div>
																									                <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
       <ul class="nav navbar-nav">
         <li><a href="?op=upload">Upload</a></li>
         <?php if ($_COOKIE['admin'] == 1) { 
           echo '<li><a href="?op=list">List</a></li>';
           } 
         ?>
       </ul>
     </div>
  </div>
</nav>

<?php
}

function fatal($msg) {
?><div class="article">
<h2>Error</h2>
<p><?php echo $msg;?></p>
</div><?php
exit(1);
}

function page_bottom() {
?>
        <footer>
            <div class="row">
                <div class="col-lg-12">
		<p>Copyright &copy; Non Profit Satire 2017</p>
                </div>
            </div>
            <!-- /.row -->
        </footer>

    </div>
    <!-- /.container -->

    <!-- jQuery -->
    <script src="js/jquery.js"></script>

	    <!-- Bootstrap Core JavaScript -->
		        <script src="js/bootstrap.min.js"></script>

	</body>

		</html>
<?php
ob_end_flush();
}

register_shutdown_function('page_bottom');

page_top($op);

if(!(include $op . '.php'))
// if(!(include $op))
    fatal('no such page');
?>
