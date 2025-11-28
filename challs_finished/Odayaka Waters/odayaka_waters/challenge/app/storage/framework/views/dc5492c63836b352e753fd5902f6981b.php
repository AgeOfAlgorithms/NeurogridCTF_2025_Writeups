<!doctype html>
<html lang="en" class="h-full">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?php echo e($title ?? config('app.name', 'Odayaka Waters')); ?></title>
  <?php echo app('Illuminate\Foundation\Vite')(['resources/css/app.css','resources/js/app.js']); ?>
  <meta name="csrf-token" content="<?php echo e(csrf_token()); ?>">
  <link rel="icon" href="<?php echo e(asset('favicon.ico')); ?>" sizes="any">
</head>
<body class="min-h-screen" style="color: var(--ow-text);">
  
  
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>

  <header class="ow-header">
    <div class="ow-container">
      <a href="<?php echo e(auth()->check() ? route('waters') : url('/')); ?>" class="ow-brand">
        Odayaka Waters <i class="ow-sakura"></i>
      </a>
      <nav class="ow-nav">
        <?php if(auth()->guard()->check()): ?>
          
          <?php if(auth()->user()->role === 'admin'): ?>
            <a class="ow-link" href="<?php echo e(route('admin.logs')); ?>">Logs</a>
          <?php endif; ?>

          <a class="ow-link" href="<?php echo e(route('waters')); ?>"> Chat </a>
          <span class="ow-user"><?php echo e(auth()->user()->name); ?></span>
          <form method="POST" action="<?php echo e(route('logout')); ?>">
            <?php echo csrf_field(); ?>
            <button class="ow-btn ow-btn--small" type="submit">Logout</button>
          </form>
        <?php else: ?>
          <a class="ow-link" href="<?php echo e(route('login')); ?>">Login</a>
          <a class="ow-link" href="<?php echo e(route('register')); ?>">Register</a>
        <?php endif; ?>
      </nav>
    </div>
  </header>

  <main class="ow-container" style="position:relative; z-index: 1;">
    <?php echo $__env->yieldContent('content'); ?>
  </main>

  
  <div id="ambient-root" style="position:fixed; inset:0; z-index:0;"></div>
</body>
</html>
<?php /**PATH /home/pyp/Misc/CTF/HTB/HTB-Made-Challenge/Secure-Coding/BATCH3/Challenges/1. Method Confusion/challenge/app/resources/views/layouts/app.blade.php ENDPATH**/ ?>