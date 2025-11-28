<?php if(session('success')): ?>
  <div class="ow-alert" style="margin-bottom:10px; padding:10px; border-radius:8px; background:#e6ffed; border:1px solid #b7eb8f;">
    <?php echo e(session('success')); ?>

  </div>
<?php endif; ?>

<?php if(session('error')): ?>
  <div class="ow-alert" style="margin-bottom:10px; padding:10px; border-radius:8px; background:#fff1f0; border:1px solid #ffa39e;">
    <?php echo e(session('error')); ?>

  </div>
<?php endif; ?>

<?php if($errors->any()): ?>
  <div class="ow-alert" style="margin-bottom:10px; padding:10px; border-radius:8px; background:#fff7e6; border:1px solid #ffd591;">
    <ul style="margin:0; padding-left:18px;">
      <?php $__currentLoopData = $errors->all(); $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $error): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
        <li><?php echo e($error); ?></li>
      <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
    </ul>
  </div>
<?php endif; ?>



<?php $__env->startSection('content'); ?>
  <section class="ow-card" style="max-width: 520px; margin: 0 auto;">
    <h1 class="ow-title" style="font-size:1.25rem;">Create account</h1>
    <div class="ow-subtle" style="margin-top:4px;">穏やかな水 — Odayaka Waters</div>
    <div class="ow-divider"></div>

    <form method="POST" action="<?php echo e(url('/register')); ?>" class="grid" style="gap: 10px;">
      <?php echo csrf_field(); ?>

      <div class="ow-field">
        <label class="ow-label" for="name">Name</label>
        <input id="name" name="name" class="ow-input" value="<?php echo e(old('name')); ?>" required minlength="2" maxlength="80"
               placeholder="Kenshin S." autocomplete="name">
      </div>

      <div class="ow-field">
        <label class="ow-label" for="email">Email</label>
        <input id="email" type="email" name="email" class="ow-input" value="<?php echo e(old('email')); ?>" required
               placeholder="you@example.com" autocomplete="email">
      </div>

      <div class="ow-field">
        <label class="ow-label" for="password">Password <span style="opacity:.7;">(min 12 chars)</span></label>
        <input id="password" type="password" name="password" class="ow-input" required minlength="12"
               placeholder="••••••••••••" autocomplete="new-password">
      </div>

      <div style="display:flex; align-items:center; justify-content:space-between; gap: 12px; margin-top: 6px;">
        <button class="ow-btn" type="submit">Create account</button>
        <div class="ow-subtle">Have an account? <a href="<?php echo e(route('login')); ?>" class="ow-link">Login</a></div>
      </div>
    </form>
  </section>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /home/pyp/Misc/CTF/HTB/HTB-Made-Challenge/Secure-Coding/BATCH3/Challenges/1. Method Confusion/challenge/app/resources/views/auth/register.blade.php ENDPATH**/ ?>