<?php $__env->startSection('content'); ?>
  <section class="ow-card" style="max-width: 520px; margin: 0 auto;">
    <h1 class="ow-title" style="font-size:1.25rem;">Login</h1>
    <div class="ow-subtle" style="margin-top:4px;">穏やかな水 — Odayaka Waters</div>
    <div class="ow-divider"></div>

    <form method="POST" action="<?php echo e(url('/login')); ?>" class="grid" style="gap: 10px;">
      <?php echo csrf_field(); ?>

      <div class="ow-field">
        <label class="ow-label" for="email">Email</label>
        <input id="email" type="email" name="email" class="ow-input"
               value="<?php echo e(old('email')); ?>" required autocomplete="email"
               placeholder="you@example.com" autofocus>
      </div>

      <div class="ow-field">
        <label class="ow-label" for="password">Password</label>
        <input id="password" type="password" name="password" class="ow-input"
               required autocomplete="current-password" placeholder="••••••••••••">
      </div>

      <div style="display:flex; align-items:center; justify-content:space-between; margin-top: 2px;">
        <label class="ow-label" style="display:inline-flex; align-items:center; gap:8px;">
          <input type="checkbox" name="remember" style="accent-color:#5cc2c9;">
          <span>Remember me</span>
        </label>

        <button class="ow-btn" type="submit">Login</button>
      </div>

      <div class="ow-divider"></div>
      <p class="ow-subtle" style="margin:0;">
        New here? <a href="<?php echo e(route('register')); ?>" class="ow-link">Create an account</a>
      </p>
    </form>
  </section>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /home/pyp/Misc/CTF/HTB/HTB-Made-Challenge/Secure-Coding/BATCH3/Challenges/1. Method Confusion/challenge/app/resources/views/auth/login.blade.php ENDPATH**/ ?>